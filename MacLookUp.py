#!/usr/bin/env python2
__author__ = "Patricia Wilthew"

"""Uses Wireshark manufacturer database, which is a list of OUIs
and MAC addresses compiled from a number of sources, to return
a manufacturer's name given a MAC. """
import urllib2

def get_mac_dictionary():
    """Returns a dictionary of MAC prefixes and their manufacturer
    based on Wireshark's manufacturer database."""

    response = urllib2.urlopen('https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf')
    html = response.read()

    mac_lookup = {}

    for ln in html.splitlines():
        if ('#' in ln) or (ln == ''):
            continue
    
        mac, manuf = ln.split()[0:2]
        mac_lookup[mac] = manuf

    return mac_lookup


def get_manufacturer(mac, mac_lookup):
    """Returns the manufacturer of a MAC given a dictionary of
    MAC prefixes and their manufacturer."""

    mac = mac.upper()
    new_mac = []

    for i in mac.split(':'):
        
        if len(i)==1:
            j = '0' + i
        else:
            j = i
        new_mac.append(j)

    new_mac = ':'.join(new_mac)

    if new_mac in mac_lookup.keys():
        return mac_lookup[new_mac]
    
    if new_mac[0:8] in mac_lookup.keys():
        return mac_lookup[new_mac[0:8]]

    else:
        return 'Not found'


def main():

    dic = get_mac_dictionary()
    print get_manufacturer('98:90:96:ac:79:a9', dic)


if __name__ == '__main__':
    main()
