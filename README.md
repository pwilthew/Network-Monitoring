# Purpose
The purpose of this project is to build and maintain a database that contains all of the devices connected to a switch. 
The project uses `snmpwalk` to get all the needed information from the switch.

The script is able to determine if:

    A new device appears on the network.
    A new MAC, that is not proprietary of Cisco, appears on the network on a VLAN known to be for phones.
    A MAC appears on the MAC table but does not appear on the ARP table; the device is not using IPv4.
    A MAC shows up on a VLAN in which it is not allowed; the allowed_vlan_list column of the database table should be manually populated in the format "100, 120, 300", for example.
    A switch port that is not considered a trunk port is assoociated with more than one MAC. Possible rogue equipment.

# Scripts/Files Organization
The polling script would initially create a database table and populate it. The same script is run periodically to detect new and suspicious devices and send email alerts. Setting up a cronjob that runs every hour would be ideal. 

The polling script contains the paths to files that contain the DB credentials, the SNMP credentials of the switch and the firewall, and the VLANs information (for example, vlan-101 is the phones' vlan). It has a function called *populate_vlans_ids()*, which uses `snmpwalk` to get a list of the VLANs present on the switch. These VLANs are stored in a global list called *VLANS_IDS*.

The polling script uses functions in netwatch.py to get the rest of the information with `snmpwalk`, to create and populate database tables, to detect suspicious devices, and to send email alerts.

And finally, there is the library *MacLookUp.py* which is used by the function *update_manufacturer()* in *netwatch.py* to get the manufacturer of a device given its MAC prefix.

# Database
The database table is named as specified in the SNMP credentials file that the polling script reads; that is, the name on last line of snmp_switch.txt

The table has the following description:

if_index INT(5) NOT NULL,           This is the interface index as seen by the switch
mac VARCHAR(50) NOT NULL,           Physical address of device
vlan VARCHAR(5) NOT NULL,           VLAN where device was found
name VARCHAR(120),                  Name of device as seen by the switch
staff_name VARCHAR(120),            Name of employee who uses the device. **Manually populated**
description VARCHAR(120),           Description of device as seen by the switch
switch_port INT(5),                 Physical switch port the device was found on
manufacturer VARCHAR(120),          Manufacturer of device. Automatically populated with the help of MacLookUp.py
allowed_vlan_list VARCHAR(120),     Comma separated list of VLANs in which the device is accepted (format example: '1, 3, 4'). **Manually populated**
most_recent_ipv4 VARCHAR(50),       Last IPv4 address seen by the switch. If the switch does not route the device, then the address is obtained from the firewall
most_recent_ipv6 VARCHAR(50),       Last IPv6 address seen by the switch, if applicable
is_uplink VARCHAR(1),               If the port is considered a trunkport. `show run` will show which ports have `switchport mode trunk`. **Manually populated**
last_seen TIMESTAMP,                The last time the device was seen by the switch
most_recent_detection TIMESTAMP,    This is called ifLastChange, or interface last change
is_new VARCHAR(1),                  Used by the script to perform certain operations with only the most recently found devices
id INT(4),                          This is irrelevant. phpMyEdit is not set to use triple keys so this column solves that issue. It is dynamically assigned every time
PRIMARY KEY(if_index, mac, vlan),   Because there can be a device in more than one VLAN and with more than one interface index, the key is triple to be able to identify all unique connections.
CONSTRAINT uniq UNIQUE(if_index, mac, vlan)

# How it works
* The script will create the table it needs, if it does not exist, yet using *netwatch.create_table()*.

* The global VLANs' list will be populated with *populate_vlans_ids()*.

* Then *netwatch.retrieve_indexes_macs()* will execute three `snmpwalk` commands to get three different lists from the switch (a baseport-index list, a MAC-baseport list, and a MAC list). 

The reason why the third one is necessary is that the MAC-baseport list shows the MAC address in ASCII representation, and of course, most of the characters in a MAC address are not printable and there is no way to find out the actual hex numbers. But I noticed that the MAC-baseport list and the MAC list had exactly the same lenght and that the MAC addresses on each line actually corresponded to each other. So, pairing the two lists together with zip() made sense. The goal was to associate Indexes with MAC addresses based on the two lists, baseport-index and MAC-baseport. A list of lists with the format *[ [if1, mac1, vlan1], [if2, mac2, vlan2], .. ]* is returned.

* The list of lists returned from the previous function is one of the inputs of *netwatch.update_indexes_macs_vlans()*, which is the function in charge of inserting or updating entries on the table. It will update its `last_seen` column on the entries that existed. If an entry was not in the table but is in the respective cemetery table (which contain devices that existed in the past), then it will insert it to the table with extra fields that were manually populated in the past; such as `staff_name`, `allowed_vlan_list`, and `is_uplink`. And finally, if the (index, mac, vlan) is not in any of the tables, then inserts it with the column `is_new` set to 'Y'.

* *netwatch.update_ipv4_addresses()* and *netwatch.update_ipv6_addresses()* simply get and update the `most_recent_ipv4` and `most_recent_ipv6` columns of each device if they are found in the `snmpwalk` output of the switch or the firewall.

* *netwatch.update_descriptions()*, *netwatch.update_last_detection()*, and *netwatch.update_names()* will update the `description`, `most_recent_detection`, and the `name` columns of each device if they are found with `snmpwalk`.

* *netwatch.update_manufacturer()* will update the `manufactuter` column of each device based on the MAC prefix lookup specified in MacLookUp.py.

* *netwatch.detect_suspicious_devices()* initially gets the entries that are considered new based on `is_new = 'Y'`. For each new device, it will check is `allowed_vlan_list` column and see if the number in `vlan` is included in that list. Then, if the device is on the phones' VLAN, it will check whether its `manufacturer` is Cisco. And finally, it will check if both `most_recent_ipv4` and `most_recent_ipv6` are empty. This function will return a string specifying the messages to be included in the email alert.

* *netwatch.detect_non_unique_switch_ports()* will get all the devices which were recently seen. It creates a dictionary of {switch_port -> MAC} in order to detect when a switch port is used by more than one device. This function also returns a string specifying the messages to be included in the email alert.

* *netwatch.notice_email()* will get the message to be included in the alert email as a parameter and will send the email.

* *netwatch.set_is_new_to_N()* will set the column `is_new` to 'N' for all entries.

* *netwatch.populate_id()* is used to fill the column `id` of all entries with integers. As said before, this column is only useful for phpMyEdit, which does not like triple keys.

* *netwatch.remove_old()* will remove entries which `last_seen` column contains a date older than 10 days, but before, it will insert some of their columns in a cemetery table, as they might be used in the future.

