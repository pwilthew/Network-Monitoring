#!/usr/bin/env python2
__author__ = "Patricia Wilthew"

"""Usage: ./poll_switch.py

The purpose of this script is to populate and/or update a
database table with information about the devices connected 
to a switch stack Cisco 2960XR."""
import MySQLdb
import subprocess
import MacLookUp
import netwatch

# Global list of triples [Interface Index ID, MAC address, VLAN]
list_if_mac_vlan = []

# Global VLAN's IDs list
VLANS_IDS = []

# Open file with database credentials
file_name = 'db_creds.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
username, db_name, password = creds[0:3]

# Open file with the switch SNMP credentials and the database table
# name that will store the devices connected to the switch 
file_name = 'snmp_switch.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
version, security, user, auth_protocol, auth_password,\
priv, priv_password, host, table_name = creds[0:9]

# Open file with the firewall's SNMP credentials 
file_name = 'snmp_firewall.txt'
file_object = open(file_name,'r')
creds = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
fversion, fsecurity, fuser, fauth_protocol, fauth_password,\
fpriv, fpriv_password, fhost = creds[0:8]

# Open file with VLAN numbers and their use
file_name = 'vlans_switch.txt'
file_object = open(file_name,'r')
lines = [(x.split(': '))[1] for x in (file_object.read()).splitlines()]

# Store them in variables
phones_vlan, admins_vlan = lines[0:2]


def populate_vlans_ids():
    """Populates a global list of the found VLANs IDs."""

    # Arguments to be used in snmpwalk
    arg = ['-m' + VLAN_IF_TABLE_MOD, '-v' + version, '-l' + security,\
           '-u' + user, '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host, 'vtpVlanState']

    out = subprocess.Popen(['snmpwalk'] + arg, 
                           stdout=subprocess.PIPE).communicate()[0]
    out_list = out.splitlines()

    for item in out_list:
        vlan = (item.split(' = ')[0]).split('.')[-1]
        
        if int(vlan) > 1 and int(vlan) < 1000:
            VLANS_IDS.append(vlan)

    return


def main():
    """Main program."""

    # Open database connection
    db = MySQLdb.connect(user=username,db=db_name,passwd=password)

    # Prepare a cursor object
    cursor = db.cursor()

    # Query to determine if table_name exists
    check = """
               SHOW TABLES LIKE '%s'
            """ % (table_name)

    # Boolean variable that holds True if a table_name exists
    table_existed = cursor.execute(check)
 
    if not table_existed:
        print '-> Creating table %s...' % (table_name)
        netwatch.create_table(db, table_name)

    print '-> Retrieving VLAN ids...'
    populate_vlans_ids()

    print '-> Retrieving interface indexes, mac addresses...'
    netwatch.retrieve_indexes_macs(VLANS_IDS, version, security,\
                          user, auth_protocol, auth_password,\
                          priv, priv_password, host, list_if_mac_vlan)

    print '-> Updating or inserting interface indexes, mac addresses, and vlans...'
    netwatch.update_indexes_macs_vlans(db, table_name, list_if_mac_vlan)

    print '-> Adding known ipv4 addresses...'
    netwatch.update_ipv4_addresses(db, table_name, version, security,\
                                   user, auth_protocol, auth_password,\
                                   priv, priv_password, host, fversion,\
                                   fsecurity, fuser, fauth_protocol,\
                                   fauth_password, fpriv, fpriv_password,\
                                   fhost)

    print '-> Adding descriptions...'
    netwatch.update_descriptions(db, table_name, version, security, user,\
                                 auth_protocol, auth_password, priv,\
                                 priv_password, host)

    print '-> Adding most recent detection dates...'
    netwatch.update_last_detection(db, table_name, version, security, user,\
                                   auth_protocol, auth_password, priv,\
                                   priv_password, host)
    
    print '-> Adding devices\' names on new devices only, if found...'
    netwatch.update_names(db, table_name, version, security, user, auth_protocol,\
                          auth_password, priv, priv_password, host)

    print '-> Adding manufacturer...'
    netwatch.update_manufacturer(db, table_name)

    print '-> Detecting new and/or suspicious devices...'
    message1 = netwatch.detect_suspicious_devices(db, table_name, phones_vlan)
    message2 = netwatch.detect_non_unique_switch_ports(db, table_name)

    print '-> Sending email alerts, if needed...'
    if message1 != '':
        netwatch.notice_email(message1+message2, table_name)
        print message1+message2

    print '-> Updating column is_new to \'N\' and populating \'id\'...'
    netwatch.set_is_new_to_N(db, table_name)
    netwatch.populate_id(db, table_name)
 
    print '-> Removing devices not seen within more than 10 days and inserting them in a cemetery table...'
    netwatch.remove_old(db, table_name)

    db.close()


if __name__ == '__main__':
    main()


