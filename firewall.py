#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from math import ceil
import re
import socket
import struct
import time
import binascii

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.lst = []
        self.countries = {}

        for line in open(config['rule']):
            if (len(line) != 0 and (not line.isspace())):
                line = line.lstrip()
                line = line.rstrip()
                if(line[0] != '%' and line != '\n'):
                    line = re.sub(' +', ' ', line.lower())
                    line = line.rstrip('\n')
                    parts = line.split(" ")
                    self.lst.append(parts)

        for line in open('geoipdb.txt'):
            if (len(line) != 0 and (not line.isspace())):
                line = line.lstrip()
                line = line.rstrip()
                if(line[0] != '%' and line != '\n'):
                    line = re.sub(' +', ' ', line.lower())
                    line = line.rstrip('\n')
                    src_ip, dest_ip, country = line.split(" ")
                    src_ip_num = struct.unpack('!L', socket.inet_aton(src_ip))[0]
                    dest_ip_num = struct.unpack('!L', socket.inet_aton(dest_ip))[0]
                    self.update_dict(country, src_ip_num, dest_ip_num, self.countries)

    """ Updates the dictionary."""
    def update_dict(self, code, src_ip_num, dest_ip_num, countries):
        if (code not in countries.keys()):
            countries[code] = []
        countries[code].append((src_ip_num, dest_ip_num))

    """ Performs binary search on the countries and returns True
         if the ip_address is in range, else it returns False. """
    def binary_search(self, countries, code, ip_address):
        imax = len(countries[code]) - 1
        imin = 0
        while(imax >= imin):
            imid = int(ceil(imin + ((imax - imin) / 2)))
            if(ip_address >= countries[code][imid][0]
                and ip_address <= countries[code][imid][1]):
                return True #in the range.
            elif(ip_address < countries[code][imid][0]):
                imax = imid - 1
            else:
                imin = imid + 1
        return False #'code not found in range'

    """ Checks the packet to make sure the IPv4 address is valid. Upon
        verifying that the addresses in the IP packet are valid, method
        returns True. Else, it returns False. """
    def valid_IP_address(self, ext_addr):
        try:
           socket.inet_ntoa(ext_addr)
           return True
        except socket.error:
           return False

    def obtain_fields(self, pckt):
        try:
            protocol = struct.unpack('!B', pckt[9:10]) # (integer,)
            total_length = struct.unpack('!H', pckt[2:4])
            return self.strip_format(protocol), self.strip_format(total_length)
        except struct.error:
            return None, None

    def valid_ip_header(self, pckt):
        try:
            ip_header = struct.unpack('!B', pckt[0:1])
            return self.strip_format(ip_header)
        except struct.error:
            return None

    def get_udp_length(self, pckt, startIndex):
        try:
            length = struct.unpack('!H', pckt[startIndex + 4 : startIndex + 6])
            return self.strip_format(length)
        except struct.error:
            return None

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pckt_dir, pckt):
        ip_header = self.valid_ip_header(pckt)
        if (ip_header == None):
            return
        ip_header = ip_header & 0x0f
        if (ip_header < 5):
            return

        protocol, total_length = self.obtain_fields(pckt)
        if (protocol == None and total_length == None):
            return

        if (total_length != len(pckt)):
            return
        
        if (self.protocol_selector(protocol) == None):
            self.send_packet(pckt, pckt_dir)
            return

        src_addr, dst_addr, pckt_dir = pckt[12:16], pckt[16:20], self.packet_direction(pckt_dir)
        if (pckt_dir == 'incoming'):
            external_addr = src_addr
        else:
            external_addr = dst_addr
        if not (self.valid_IP_address(external_addr)): # check valid address.
            return

        if (protocol == 6): # TCP
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
            else:
                external_port = self.handle_external_port(pckt, ((ip_header) * 4) + 2)
            if (external_port == None): # drop packet due to port socket error.
                return

        elif (protocol == 1): # ICMP
            type_field = self.handle_icmp_packet(pckt, (ip_header * 4))
            if (type_field == None):
                return

        elif (protocol == 17): # UDP
            udp_length = self.get_udp_length(pckt, (ip_header * 4))
            if (udp_length == None or udp_length < 8):
                return
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
                if (external_port == None):
                    return
            else:
                external_port = self.handle_external_port(pckt, ((ip_header) * 4) + 2)
                if (external_port == None):
                    return
                if (self.strip_format(external_port) == 53):
                    dns_offset = (ip_header * 4) + 8
                    QDCOUNT, pckt_domain_name, QTYPE, QCLASS = self.parseDNS(dns_offset, pckt) # Check this.
                    if not (self.check_dns_fields(QDCOUNT, QTYPE, QCLASS)):
                        return
                    else:
                        QDCOUNT = self.strip_format(QDCOUNT)
                        QTYPE = self.strip_format(QTYPE)
                        QCLASS = self.strip_format(QCLASS)

        verdict = "pass"
        for rule in self.lst:
            if (len(rule) == 4):
                verdict_rule, rule_protocol, ext_IP, ext_port = rule[0], rule[1], rule[2], rule[3]
                if (ext_IP == '0.0.0.0/0'):
                    ext_IP = "any"
                # Check if the pckt protocol matches the rules protocol.
                if (self.protocol_selector(protocol) != rule_protocol):
                    continue
                # Checking the IP field
                if (ext_IP != 'any'):
                    if not (self.check_externalIP(ext_IP, external_addr)):
                        continue
                # Checking the port field
                if (ext_port != 'any'):
                    if (self.protocol_selector(protocol) != 'icmp'):
                        if not (self.check_externalPort(ext_port, self.strip_format(external_port))):
                            continue
                    else:
                        if not (self.check_externalPort(ext_port, type_field)):
                            continue
            elif (len(rule) == 3):
                verdict_rule, rule_p, domain_name = rule[0], rule[1], rule[2]
                if (rule_p == 'dns' and self.protocol_selector(protocol) == 'udp'): # rule == DNS
                    if (pckt_dir == 'outgoing' and self.strip_format(external_port) == 53):
                        if not (self.matches_dns_rules(pckt_domain_name, domain_name, QDCOUNT, QTYPE, QCLASS)):
                            continue
                    else:
                        continue
                else:
                    continue

            verdict = verdict_rule 
        if (verdict == 'pass'):
            self.send_packet(pckt, pckt_dir)

    """ Sends the packet in the correct direction."""
    def send_packet(self, pckt, pckt_dir):
        if (pckt_dir == 'incoming'):
            self.iface_int.send_ip_packet(pckt)
        else:
            self.iface_ext.send_ip_packet(pckt)

    """ Protocol Selector."""
    def protocol_selector(self, protocol):
        if (protocol == 1):
            return "icmp"
        elif (protocol == 6):
            return 'tcp'
        elif (protocol == 17):
            return 'udp'
        return None

    """ IP Protocol Rules """

    """ Returns True if the protocol of the packet is either TCP, UDP, or ICMP.
        Else, the method returns False. """
    def check_protocol(self, protocol):
        return (protocol == 'tcp') or (protocol == 'udp') or (protocol == 'icmp') 

    """ Checks the external IP address field. Returns True if it is valid, else it
        return False. """
    def check_externalIP(self, data, external_ip):
        # Convert from bytes to IP address string.
        external_ip = socket.inet_ntoa(external_ip) # 1.2.3.4
        # if it is a 2 - byte country code
        if (len(data) == 2):
            # Convert from string to integer.
            try:
                external_ip = struct.unpack('!L', socket.inet_aton(external_ip))[0]
                if not (data.lower() in self.countries.keys()):
                   return False
                return self.binary_search(self.countries, data.lower(), external_ip)
            except struct.error:
                return False
        else:
            # if it is a single IP address.
            if(self.is_IP_Prefix(data) == -1): # 1.2.3.4
                return data == external_ip
            else: # if data is IP prefix.
                return self.range_for_CIDR(data, external_ip)

    """ Returns True if the external IP address is within the range of the
        IP prefix."""
    def within_range(self, start_port, end_port, external_ip):
        return external_ip >= start_port and external_ip <= end_port

    """ Check if the data is an IP prefix."""
    def is_IP_Prefix(self, data):
        return data.find('/')

    """ Checks the External port. If the external port meets the requirements,
        then True is returned. Else, False is returned."""
    def check_externalPort(self, data, external_port):
        # A single value.
        if(data.find('-') == -1):
            return external_port == int(data)
        else: # if it is in a range.
            lst = data.split('-')
            lst[0] = lst[0].lstrip().rstrip()
            lst[1] = lst[1].lstrip().rstrip()
            return self.within_range(int(lst[0]), int(lst[1]), external_port)

    """ Returns True if packet info matches DNS Protocol Rules, else returns False."""
    def matches_dns_rules(self, dns_domain_name, rules_domain_name, QDCOUNT, QTYPE, QCLASS):
        return self.dns_match(dns_domain_name, rules_domain_name) and QDCOUNT == 1 and (QTYPE == 1 or QTYPE == 28) and (QCLASS == 1)

    """ Returns the direction of the packet in a string."""
    def packet_direction(self, direction):
        if (direction == PKT_DIR_OUTGOING):
            return 'outgoing'
        else:
            return 'incoming'

    def check_dns_fields(self, QDCOUNT, QTYPE, QCLASS):
        return QDCOUNT != None and QTYPE != None and QCLASS != None

    """Parse DNS packet and returns the QDCOUNT, QTYPE, QCLASS."""
    def parseDNS(self, dns_offset, pckt):
        try:
            QDCOUNT = struct.unpack('!H', pckt[dns_offset + 4 : dns_offset + 6])
            q_offset = dns_offset + 12
            domain_name, qname_len = self.assemble_domain_name(pckt, q_offset)
            QTYPE_offset = q_offset + qname_len + 1
            QTYPE = struct.unpack('!H', pckt[QTYPE_offset : QTYPE_offset + 2])
            QCLASS_offset = QTYPE_offset + 2
            QCLASS = struct.unpack('!H', pckt[QCLASS_offset : QCLASS_offset + 2])
            return QDCOUNT, domain_name.lower(), QTYPE, QCLASS
        except struct.error:
            return None, None, None, None

    """ Assembles the domain name from the DNS QNAME Field """
    def assemble_domain_name(self, pckt, startIndex):
        domain_name = ""
        i, qname_length = startIndex, 0
        while((ord(pckt[i]) != 0)  and (i < len(pckt))):
            length = ord(pckt[i])
            count = 0
            i += 1
            qname_length += 1
            while (count < length):
                domain_name += chr(ord(pckt[i]))
                i += 1
                count += 1
                qname_length += 1
            domain_name += '.'
        return domain_name[0: len(domain_name) - 1], qname_length

    """ Strips the parentheses and comma off the number and converts string to int."""
    def strip_format(self, format_str):
        new_str = str(format_str)
        return int(new_str[1: len(new_str) - 2])

    """ Returns the external port and checks to see if there is a socket error. If
        the port is valid, then it returns a number, else it returns 'None'. """
    def handle_external_port(self, pckt, startIndex):
        try:
            ext_port = pckt[startIndex : startIndex + 2]
            ext_port = struct.unpack('!H', ext_port)
            return ext_port
        except struct.error:
            return None

    """ Returns the TYPE field for the IMCP packet."""
    def handle_icmp_packet(self, pckt, startIndex):
        try:
            type_field = pckt[startIndex : startIndex + 1]
            type_field = struct.unpack('!B', type_field)
            return self.strip_format(type_field)
        except struct.error:
            return None

    """ Checks to see if the dns domain name == rules domain name. """
    def dns_match(self, dns_domain_name, rules_domain_name):
        if (rules_domain_name.find('*') == -1):
            return  rules_domain_name == dns_domain_name
        else:
            index = rules_domain_name.find('*')
            if (len(rules_domain_name) == 1 and index == 0):
                return True
            start = dns_domain_name.find(rules_domain_name[index + 1:])
            if ((start) >= 0):
                if (dns_domain_name[start:] == rules_domain_name[index + 1:]):
                    return True
                else:
                    return False
            return False

    def range_for_CIDR(self, ip_cidr, ip_addr):

        ip, network = ip_cidr.split('/')
        network = int(network)
        host =  32 - network

        ip_split = [format(int(x), '08b') for x in ip.split('.')]
        ip_value = str(ip_split[0]) + str(ip_split[1]) + str(ip_split[2]) + str(ip_split[3])
        ip_int = int(ip_value, 2)

        i = host + 1
        bk = 1 << host
        while i < 32:
            bk += 1 << i
            i+=1

        bottom_int = ip_int & bk
        i = 0
        tk = 0
        while i < host:
            tk += 1 << i
            i+=1

        top_int = bottom_int + tk
        ip_addr_split = [format(int(x), '08b') for x in ip_addr.split('.')]
        ip_addr_value = str(ip_addr_split[0]) + str(ip_addr_split[1]) + str(ip_addr_split[2]) + str(ip_addr_split[3])
        ip_addr_int = int(ip_addr_value, 2)

        if (ip_addr_int>=bottom_int) and (ip_addr_int <= top_int):
           return True
        else:
            return False
