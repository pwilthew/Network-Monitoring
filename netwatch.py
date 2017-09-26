#!/usr/bin/env python2
__author__ = "Patricia Wilthew"

"""Auxiliary functions' library used by poll_switch.py to 
populate and/or update a database table with information 
about the devices connected to a switch."""
import MySQLdb
import subprocess
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import *
import MacLookUp

def create_table(db, table_name):
    """Creates the DB table necessary for for this program."""

    # Prepare a cursor object
    cursor = db.cursor()

    # Query to create a new table that will contain all the devices
    # on the network. It will be called table_name
    create = """
                CREATE TABLE %s   (
                                   if_index INT(5) NOT NULL,
                                   mac VARCHAR(50) NOT NULL, 
                                   vlan VARCHAR(5) NOT NULL,
                                   name VARCHAR(120),
                                   staff_name VARCHAR(120),
                                   description VARCHAR(120),
                                   switch_port INT(5), 
                                   manufacturer VARCHAR(120),
                                   allowed_vlan_list VARCHAR(120),
                                   most_recent_ipv4 VARCHAR(50),
                                   most_recent_ipv6 VARCHAR(50),
                                   is_uplink VARCHAR(1),
                                   last_seen TIMESTAMP,
                                   most_recent_detection TIMESTAMP,
                                   is_new VARCHAR(1),
                                   id INT(4),
                                   PRIMARY KEY(if_index, mac, vlan),
                                   CONSTRAINT uniq UNIQUE(if_index, mac, vlan)
                                  )
             """ % (table_name)
    try:
        cursor.execute(create)
        db.commit()
    except:
        print 'Error in table creation:', cursor._last_executed
        db.rollback()

    return


def retrieve_indexes_macs(VLANS_IDS, version, security, user, auth_protocol,\
                          auth_password, priv, priv_password, host, list_if_mac_vlan):
    """Populates the global list of interface indexes and their\
    respective MAC addresses and VLANs."""

    for vlan in VLANS_IDS:

        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user,\
               '-a' + auth_protocol, '-A' + auth_password,\
               '-x' + priv, '-X' + priv_password, host,\
               'BasePortIfIndex']

        output = subprocess.Popen(['snmpwalk'] + arg, 
                                  stdout=subprocess.PIPE).communicate()[0]
        
        baseport_index_list = output.splitlines()

        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user,\
               '-a' + auth_protocol, '-A' + auth_password,\
               '-x' + priv, '-X' + priv_password, host,\
               'dot1dTpFdbPort']

        output = subprocess.Popen(['snmpwalk'] + arg,
                                  stdout=subprocess.PIPE).communicate()[0]

        mac_baseport_list = output.splitlines()

        # Arguments to be used in snmpwalk
        arg = ['-m' + 'BRIDGE-MIB' , '-n' + 'vlan-' + vlan,\
               '-v' + version, '-l' + security, '-u' + user,\
               '-a' + auth_protocol, '-A' + auth_password,\
               '-x' + priv, '-X' + priv_password, host,\
               'dot1dTpFdbAddress']

        output = subprocess.Popen(['snmpwalk'] + arg,
                                  stdout=subprocess.PIPE).communicate()[0]

        mac_address_list = output.splitlines()

        # Temporary dictionaries to represent the mapping 
        # baseport => MAC Address and
        # baseport => Interface Index ID
        dic_baseport_mac = {}
        dic_baseport_index = {}

        # Parse lists' items to get baseport and mac to populate
        # dic_baseport_mac dictionary
        for i,j in zip(mac_baseport_list, mac_address_list):
            baseport = i.split('INTEGER: ')[-1]
            mac = j.split('STRING: ')[-1]
            mac = mac.upper()
            new_mac = []

            # Format MAC
            for i in mac.split(':'):

                if len(i)==1:
                    j = '0' + i
                else:
                    j = i
    
                new_mac.append(j)

            new_mac = ':'.join(new_mac)

            dic_baseport_mac[baseport] = new_mac

        # Parse lists' items to get baseport and if index to populate
        # dic_baseport_index dictionary
        for item in baseport_index_list:
            first, second = item.split(' = ')[0:2]
            baseport = first.split('.')[-1]
            if_index = second.split(': ')[-1]
            dic_baseport_index[baseport] = if_index

        # Populate the global list_if_mac_vlan
        for baseport in dic_baseport_mac.keys():
            if baseport not in dic_baseport_index:
                continue
            if_index = dic_baseport_index[baseport]
            mac = dic_baseport_mac[baseport]
            list_if_mac_vlan.append([if_index, mac, vlan])

    print '-> Number of found devices:',len(list_if_mac_vlan)

    return


def update_indexes_macs_vlans(db, table_name, list_if_mac_vlan):
    """Updates the interface indexes, mac addresses, and vlan ids
    into the table."""

    # Prepare a cursor object
    cursor = db.cursor()

    cemetery_table = table_name + '_cemetery'

    # Insert list_if_mac_vlan content in table
    for item in list_if_mac_vlan:
        index, mac, vlan = item[0:3]

        query = """
                   SELECT * FROM %s
                   WHERE mac = '%s' AND if_index = '%s' AND vlan = '%s'
                """ % (table_name,\
                       mac,\
                       index,\
                       vlan\
                      )

        row_exists = cursor.execute(query)

        dat = datetime.now()

        # If exact row exists, update last_seen column and continue
        if row_exists:
            update = """
                        UPDATE %s
                        SET last_seen = '%s'
                        WHERE mac = '%s' AND if_index = '%s' AND vlan = '%s'
                     """ % (table_name,\
                            dat,\
                            mac,\
                            index,\
                            vlan\
                           )

            try:
                cursor.execute(update)
                db.commit()

            except:
                print 'Error in table update: ', cursor._last_executed
                db.rollback()

            continue

        # Check if MAC exists in cemetery table (rows that were previously 
        # deleted) and get its manually entered fields like staff_name, 
        # allowed_vlan_list and is_uplink

        # Query to determine if cemetery table exists
        check = """
                   SHOW TABLES LIKE '%s'
                """ % (cemetery_table)

        # Boolean variable that holds True if a cemetery table exists
        table_existed = cursor.execute(check)        

        if table_existed:
            query = """
                       SELECT staff_name, allowed_vlan_list, is_uplink
                       FROM %s
                       WHERE mac='%s'
                    """ % (cemetery_table,\
                           mac\
                          )

            found = cursor.execute(query)

            if found:
                for result in cursor:
                    staff_name, allowed_vlan_list, is_uplink = result[0:4]

                 
                insert = """
                            INSERT INTO %s (if_index, mac, vlan, staff_name,\
                                            allowed_vlan_list, is_new,\
                                            is_uplink, last_seen)
                            VALUES ('%s', '%s', '%s', '%s', '%s', 'N', '%s', '%s')
                         """ % (table_name,\
                                index,\
                                mac,\
                                vlan,\
                                staff_name,\
                                allowed_vlan_list,\
                                is_uplink,\
                                dat\
                               )

                try:
                    cursor.execute(insert)
                    db.commit()

                except:
                    print 'Error in table insertion: ', cursor._last_executed
                    db.rollback()

                continue

        # Otherwise, just add new device to table
        # But first, let's check if the MAC exists and its allowed_vlan_list
        # is not null so we can use its value for the new entry
        select = """
                    SELECT allowed_vlan_list
                    FROM %s
                    WHERE mac='%s'
                    AND allowed_vlan_list IS NOT NULL
                 """ % (table_name,\
                        mac\
                       )

        found = cursor.execute(select)

        if found:
            for result in cursor:
                allowed_vlan_list = result[0]
                break
        else:
            allowed_vlan_list = ''

        insert = """
                    INSERT INTO %s (if_index, mac, vlan, allowed_vlan_list,\
                                    is_new, last_seen)
                    VALUES ('%s', '%s', '%s', '%s', 'Y', '%s')
                 """ % (table_name,\
                        index,\
                        mac,\
                        vlan,\
                        allowed_vlan_list,\
                        dat\
                       )

        try:
            cursor.execute(insert)
            db.commit()

        except:
            print 'Error in table insertion: ', cursor._last_executed
            db.rollback()

    return


def update_ipv4_addresses(db, table_name, version, security, user,\
                          auth_protocol, auth_password, priv, priv_password,\
                          host, fversion, fsecurity, fuser, fauth_protocol,\
                          fauth_password, fpriv, fpriv_password, fhost):
    """Populates the ipv4 address column of the table."""

    # First, get ARP entries of devices not routed by switch
    query_firewall(db, table_name, fversion, fsecurity, fuser, fauth_protocol,\
                   fauth_password, fpriv, fpriv_password, fhost)

    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'ipNetToMediaPhysAddress']

    arp_table = subprocess.Popen(['snmpwalk'] + arg,\
                                 stdout=subprocess.PIPE).communicate()[0]

    arp_table_list = arp_table.splitlines()

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse lists' items to get ip and mac addresses to insert into DB table
    for row in arp_table_list:
        string, mac = (row.split(' = STRING: '))[0:2]
        
        dot = '.'
        string = string.split('IP-MIB::ipNetToMediaPhysAddress.')
        ip = dot.join(((string[1]).split('.'))[1:5])

        update = """
                    UPDATE %s
                    SET most_recent_ipv4 = '%s'
                    WHERE mac = '%s'
                 """ % (table_name,\
                        ip,\
                        mac\
                       )
        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    return


def update_ipv6_addresses(db, table_name, version, security, user,\
                          auth_protocol, auth_password, priv, priv_password,\
                          host):
    """Populates the ipv6 address column of the table."""

    # Arguments to be used in snmpwalk
    arg = ['-m' + 'SNMPv2-SMI', '-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'mib-2.4.35.1.4']

    arp_table = subprocess.Popen(['snmpwalk'] + arg,\
                                 stdout=subprocess.PIPE).communicate()[0]

    arp_table_list = arp_table.splitlines()

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse lists's items to get mac and ipv6 addresses to insert into DB table
    for row in arp_table_list:
        if 'Hex-STRING' not in row:
            continue

        left, right = row.split(' = Hex-STRING: ')[0:2]
        colon = ':'
        mac = (colon.join(right.split(' '))).strip(':')
        
        ip_decimal_list = left.split('.')[8:24]
        ip_hex_list = ["{:02x}".format(int(x)) for x in ip_decimal_list]
        ip = colon.join([x+y for x,y in zip(ip_hex_list[::2], ip_hex_list[1::2])])

        update = """
                    UPDATE %s
                    SET most_recent_ipv6 = '%s'
                    WHERE mac = '%s'
                 """ % (table_name,\
                        ip,\
                        mac
                       )

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    return


def query_firewall(db, table_name, fversion, fsecurity, fuser, fauth_protocol,\
                   fauth_password, fpriv, fpriv_password, fhost):
    """Get the ARP entries for the MAC addresses that are routed
    by the firewall. Because some of the switch devices are being 
    routed by the firewall instead of the switch, their ARP entries
    are empty from the perspective of the switch."""

    # Arguments to be used in snmpwalk
    arg = ['-v' + fversion, '-l' + fsecurity, '-u' + fuser,\
           '-a' + fauth_protocol, '-A' + fauth_password,\
           '-x' + fpriv, '-X' + fpriv_password, fhost,\
           'ipNetToMediaPhysAddress']

    ip_mac = subprocess.Popen(['snmpwalk'] + arg,\
                              stdout=subprocess.PIPE).communicate()[0]

    ip_mac_list = ip_mac.splitlines()

    # Prepare a cursor object
    cursor = db.cursor()
 
    for ln in ip_mac_list:
        left, mac = ln.split(' = STRING: ')[0:2]
        dot = '.'
        ip = dot.join(left.split('.')[2:6])

        update = """
                    UPDATE %s
                    SET most_recent_ipv4 = '%s'
                    WHERE mac = '%s'
                 """ % (table_name,\
                        ip,\
                        mac\
                       )

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    return


def update_descriptions(db, table_name, version, security, user, auth_protocol,\
                        auth_password, priv, priv_password, host):
    """Populates the description column of the table."""

    IF_DESCRIPTION_OID = '.1.3.6.1.2.1.2.2.1.2'

    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           IF_DESCRIPTION_OID]

    if_descr = subprocess.Popen(['snmpwalk'] + arg,\
                                stdout=subprocess.PIPE).communicate()[0]

    if_descr_list = if_descr.splitlines()

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse list's items to get index and description to insert into DB table
    for row in if_descr_list:

        index, descr = row.split(' = STRING: ')[0:2]
        index = index.split('.')[-1]

        if 'GigabitEthernet' in descr:
            port = descr.split('/')[-1]

            update = """
                        UPDATE %s
                        SET description = '%s', switch_port = '%s'
                        WHERE if_index = '%s' 
                     """ % (table_name,\
                            descr,\
                            port,\
                            index\
                           )
        else:
            update = """
                        UPDATE %s
                        SET description = '%s'
                        WHERE if_index = '%s'
                     """ % (table_name,\
                            descr,\
                            index\
                           )
        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    return


def update_last_detection(db, table_name, version, security, user,\
                          auth_protocol, auth_password, priv, priv_password,\
                          host):
    """Populates the most_recent_detection column of the table."""

    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'ifLastChange']

    if_date = subprocess.Popen(['snmpwalk'] + arg,\
                               stdout=subprocess.PIPE).communicate()[0]

    if_date_list = if_date.splitlines()

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse list's items to get interface index and device's 
    # most recent detection to insert into DB table
    for row in if_date_list:
        index, ticks = row.split(' = Timeticks: ')[0:2]
        index = index.split('.')[-1]
        ticks = int((ticks.split(' ')[0])[1:-1])
        seconds = ticks/100
        delta = timedelta(seconds=seconds)
        today = datetime.now()
        dat = today - delta

        update = """
                    UPDATE %s
                    SET most_recent_detection = '%s'
                    WHERE if_index = '%s'
                 """ % (table_name,\
                        dat,\
                        index\
                       )

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    return


def update_names(db, table_name, version, security, user, auth_protocol,\
                 auth_password, priv, priv_password, host):
    """On the new entries of the table, populates the name
       column."""

    # Arguments to be used in snmpwalk
    arg = ['-v' + version, '-l' + security, '-u' + user,\
           '-a' + auth_protocol, '-A' + auth_password,\
           '-x' + priv, '-X' + priv_password, host,\
           'ifAlias']

    if_name = subprocess.Popen(['snmpwalk'] + arg,\
                               stdout=subprocess.PIPE).communicate()[0]

    if_name_list = if_name.splitlines()

    # Prepare a cursor object
    cursor = db.cursor()

    # Parse list's items to get interface index and device's 
    # name to insert into DB table
    for row in if_name_list:
        index, name = row.split(' = STRING: ')[0:2]
        index = index.split('.')[-1]

        update = """
                    UPDATE %s
                    SET name = '%s'
                    WHERE if_index = '%s'
                 """ % (table_name,\
                        name,\
                        index\
                       )

        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    return


def update_manufacturer(db, table_name):
    """Populates the manufacturer column of the table."""

    mac_lookup = MacLookUp.get_mac_dictionary()

    # Prepare a cursor object
    cursor = db.cursor()

    # Get new devices in table
    query = """
                SELECT mac
                FROM %s
            """ % (table_name)

    cursor.execute(query)

    for result in cursor:
        mac = result[0]

        manuf = MacLookUp.get_manufacturer(mac, mac_lookup)

        update = """
                    UPDATE %s
                    SET manufacturer = '%s'
                    WHERE mac = '%s'
                 """ % (table_name,\
                        manuf,\
                        mac\
                       )
        try:
            cursor.execute(update)
            db.commit()

        except:
            print 'Error in table update: ', cursor._last_executed
            db.rollback()

    return


def detect_suspicious_devices(db, table_name, phones_vlan):
    """Detects suspicious devices and triggers alerts if necessary.
       Suspicious devices might be: new devices, devices that are 
       on the phones VLAN but are not phones, and devices that do
       not have an IP address."""

    # Prepare a cursor object
    cursor = db.cursor()

    # Get new devices in table
    query = """
                SELECT mac, vlan, most_recent_ipv4, manufacturer 
                FROM %s
                WHERE is_new = 'Y'
            """ % (table_name)

    cursor.execute(query)

    message = ''

    for result in cursor:
        mac = result[0]
        vlan = result[1]
        ipv4 = result[2]
        manuf = result[3]

        message += '---Device ' + mac + ' appeared on the network--- \n'

        # Check if this device is allowed on this VLAN
        query = """
                    SELECT allowed_vlan_list 
                    FROM %s
                    WHERE mac = '%s'
                """ % (table_name,\
                       mac\
                      )

        cursor.execute(query)
        allowed = False

        for results in cursor:
            for item in results:
                if vlan in item:
                    allowed = True
                    break

        if not allowed:
            message += '\tDevice is on VLAN that is not in its allowed VLANs list. \n'

        # Determine if the MAC appears on a VLAN known to be for phones
        # and does not have a prefix that maps to Cisco
        if vlan==phones_vlan:
            if 'Cisco' not in manuf:
                message += '\tDevice is on the phones VLAN. \n'

        # If the device does not have an IP address, it may suggest
        # that a device on the network is not talking IPv4/6, which
        # should never be the case
        if ipv4 == None:
            message += '\tDevice is not on the ARP neighbor table. \n'

    return message


def detect_non_unique_switch_ports(db, table_name):
    """Detects if a switch port has more than one MAC showing on a
    a port that has not been explicitly defined as an uplink port.
    This is a way to detect if someone has plugged in a rogue
    switch or access point into the network but cloned their 
    desktop's MAC to hide it."""

    # Prepare a cursor object
    cursor = db.cursor()

    # Get all recently seen devices in table
    query = """
                SELECT mac, description, is_uplink
                FROM %s
                WHERE last_seen > (NOW() - INTERVAL 5 MINUTE)
            """ % (table_name)

    cursor.execute(query)

    dic = {}
    message = '---The following ports are being used by more than one MAC--- \n'
    flag = False

    for result in cursor:
        mac = result[0]
        description = result[1]
        is_uplink = result[2]

        if 'Y' == is_uplink:
            continue

        # Add description/port to dictionary
        if description not in dic.keys():
            dic[description] = mac

        # If port exists in dictionary
        else:
            # If MAC corresponds to previous value
            if mac == dic[description]:
                continue
 
            # If MAC is different
            flag = True

            # Add port to list of ports to report
            if description in message:
                continue

            message += description + '\n'

    if flag:
        return message

    return ''


def populate_id(db, table_name):
    """Because phpMyEdit needs a table to have a single primary key,
       this function will populate the id column of the table with
       integers."""

    # Prepare a cursor object
    cursor = db.cursor()

    # Get all devices from table
    query = """SELECT if_index, mac, vlan 
               FROM %s
               ORDER BY if_index
            """ % (table_name)

    cursor.execute(query)
    
    i = 0

    for result in cursor:
        if_index, mac, vlan = list(result)

        query = """UPDATE %s
                   SET id=%d
                   WHERE if_index = '%s' AND
                         mac = '%s' AND 
                         vlan = '%s'
                """ % (table_name,\
                       i,\
                       if_index,\
                       mac,\
                       vlan\
                      )
        try:
            cursor.execute(query)
            db.commit()

        except:
            print 'Error in table update:', cursor._last_executed
            db.rollback()

        i += 1
    
    return


def set_is_new_to_N(db, table_name):
    """When the new and/or suspicious devices were reported, make them
    Not new to avoid reporting them again on the next run."""

    # Prepare a cursor object
    cursor = db.cursor()

    # Query to set column is_new to 'N'
    set_not_new = """
                     UPDATE %s
                     SET is_new = 'N'
                  """ % (table_name)

    try:
        cursor.execute(set_not_new)
        db.commit()

    except:
        print 'Error in table update:', cursor._last_executed
        db.rollback()

    return


def remove_old(db, table_name):
    """Removes entries older than 10 days from the table and stores them in
    another table."""

    # Prepare a cursor object
    cursor = db.cursor()

    # As we want to save entries in another table before removing them,
    # create that table if it does not exist yet
    cemetery_table = table_name + '_cemetery'

    # Query to determine if cemetery_table exists
    check = """
               SHOW TABLES LIKE '%s'
            """ % (cemetery_table)

    # Boolean variable that holds True if a cemetery_table exists
    table_existed = cursor.execute(check)

    if not table_existed:
        create = """
                    CREATE TABLE %s (
                                    mac VARCHAR(50) NOT NULL, 
                                    name VARCHAR(120),
                                    staff_name VARCHAR(120),
                                    description VARCHAR(120),
                                    manufacturer VARCHAR(120),
                                    allowed_vlan_list VARCHAR(120),
                                    is_uplink VARCHAR(1),
                                    PRIMARY KEY(mac)
                                    )
                 """ % (cemetery_table)
        try:
            cursor.execute(create)
            db.commit()

        except:
            print 'Error in table creation:', cursor._last_executed
            db.rollback()

    # Insert entries to be deleted
    insert = """
                REPLACE INTO %s (mac, name, staff_name, description,\
                                 manufacturer, allowed_vlan_list, is_uplink)
                SELECT mac, name, staff_name, description, manufacturer,\
                       allowed_vlan_list, is_uplink\
                FROM %s
                WHERE last_seen < (NOW() - INTERVAL 10 DAY)
             """ % (cemetery_table,\
                    table_name\
                   )

    try:
        cursor.execute(insert)
        db.commit()

    except:
        print 'Error in table remove:', cursor._last_executed
        db.rollback()

    # Query to remove entries older than 10 days
    delete = """
                DELETE
                FROM %s
                WHERE last_seen < (NOW() - INTERVAL 10 DAY)
             """ % (table_name)
    try:
        cursor.execute(delete)
        db.commit()

    except:
        print 'Error in table remove:', cursor._last_executed
        db.rollback()

    return


def notice_email(msg, table_name):
    """Sends an email alert."""

    # Initialize SMTP server
    server = smtplib.SMTP('localhost',25)
    server.starttls()

    f = 'alerts@example.com'
    t = 'pwilthew@example.com'

    container = MIMEMultipart('alternative')
    container['Subject'] = 'Network Alert: %s' % table_name
    container['From'] = f
    container['To'] = t

    extra = 'example.com/tables/%s.php\n' % table_name
    text = msg + extra
   
    new_msg = ''

    for ln in msg.splitlines():
        new_msg += '<p>'+ln+'</p>'
 
    html = """\
              <html>
                <head></head>
                <body>
                    %s
                    <p><a href="example.com/tables/%s.php">\\
                    example.com/tables/%s.php</a>\n </p>
                </body>
              </html>
           """ % (new_msg, table_name, table_name)

    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    container.attach(part1)
    container.attach(part2)

    server.sendmail(f, t, container.as_string())
    server.quit()

    return



