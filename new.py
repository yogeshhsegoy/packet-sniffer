import socket
import struct
import sys
import os

Packet_Container = []
ip_source = ''
ip_destination = ''


def main(protocol):
    if os.name == 'posix':
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    else:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((socket.gethostbyname(socket.gethostname()), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            Recent_Packet = ["errorandler"]
            if eth_proto == 8: # IPv4
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                
                if proto == 6 and len(data) >= 20: # TCP and sufficient data
                    src_port, dest_port, sequence, acknowledgment, flags, tcp_data = tcp_segment(data)

                    if flags[2]:  # Check if PSH flag is set
                        if (src_port == 80 or dest_port == 80) and len(tcp_data) > 0:
                            http_data = http_decode(tcp_data)                                                       #8    #9
                            Recent_Packet = ["http",dest_mac, src_mac, eth_proto,version, header_length, ttl, proto, src, target, http_data]
                            
                        elif (src_port == 443 or dest_port == 443) and len(tcp_data) > 0:
                            https_data = http_decode(tcp_data)
                            Recent_Packet = ["https",dest_mac, src_mac, eth_proto,version, header_length, ttl, proto, src, target, https_data]

                            
                        elif (src_port == 21 or dest_port == 21) and len(tcp_data) > 0:
                            ftp_data = ftp_decode(tcp_data)
                            Recent_Packet = ["ftp",dest_mac, src_mac, eth_proto, version, header_length, ttl, proto, src, target, ftp_data]

                            
                        elif (src_port == 25 or dest_port == 25) and len(tcp_data) > 0:
                            smtp_data = smtp_decode(tcp_data)
                            Recent_Packet = ["smtp",dest_mac, src_mac, eth_proto, version, header_length, ttl, proto, src, target, smtp_data]

                            
                        else:
                            # Default case for other TCP packets
                            Recent_Packet = ["otherTCP",dest_mac, src_mac, eth_proto, version, header_length, ttl, proto, src, target]
                            
                    
                elif proto == 17 and len(data) >= 8: # UDP and sufficient data
                    src_port, dest_port, length, udp_data = udp_segment(data)
                    if (src_port == 53 or dest_port == 53) and len(udp_data) > 0:
                        dns_data = dns_decode(udp_data)
                        Recent_Packet = ["dns",dest_mac, src_mac, eth_proto, version, header_length, ttl, proto, src, target ,dns_data]
                        
                    else:
                        # Default case for other UDP packets
                        Recent_Packet = ["otherUDP",dest_mac, src_mac, eth_proto, version, header_length, ttl, proto, src, target, udp_data]
                        
            elif eth_proto == 1544 and protocol == 'arp': # ARP
                dest_mac, src_mac, arp_src, arp_dest = arp_packet(raw_data)
                Recent_Packet = ["arp",dest_mac, src_mac, eth_proto, arp_src, arp_dest]
                
            Packet_Container.append(Recent_Packet)
    except:
        if protocol == 'all':
            file = open('all.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'http':
                    formated = http_formatter(i)
                    
                elif i[0] == 'https':
                    formated = https_formatter(i)
                    
                elif i[0] == 'ftp':
                    formated = ftp_formatter(i)
                    
                elif i[0] == 'smtp':
                    formated = smtp_formatter(i)
                    
                elif i[0] == 'otherTCP':
                    formated = otherTCP_formatter(i)
                    
                elif i[0] == 'dns':
                    formated = dns_formatter(i)
                    
                elif i[0] == 'otherUDP':
                    formated = otherUDP_formatter(i)

                elif i[0] == 'arp':
                    formated = arp_formatter(i)
                if formated:
                    file.write(formated)
                
                





        elif protocol == 'tcp':
            file = open('tcp.txt', 'w')
            for i in Packet_Container:
                formated =''
                if i[0] == 'http':
                    formated = http_formatter(i)
                    
                elif i[0] == 'https':
                    formated = https_formatter(i)
                    
                elif i[0] == 'ftp':
                    formated = ftp_formatter(i)
                    
                elif i[0] == 'smtp':
                    formated = smtp_formatter(i)
                    
                elif i[0] == 'otherTCP':
                    formated = otherTCP_formatter(i)
                if formated:
                    file.write(formated)


        elif protocol == 'udp':
            file = open('udp.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'dns':
                    formated = dns_formatter(i)
                    
                elif i[0] == 'otherUDP':
                    formated = otherUDP_formatter(i)
                if formated:
                    file.write(formated)

        elif protocol == 'http':
            file = open('http.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'http':
                    formated = http_formatter(i)
                if formated:
                    file.write(formated)

        elif protocol == 'https':
            file = open('https.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'https':
                    formated = https_formatter(i)
                if formated:
                    file.write(formated)


        elif protocol == 'smtp':
            file = open('smtp.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'smtp':
                    formated = smtp_formatter(i)
                if formated:
                    file.write(formated)
        
        elif protocol == 'ftp':
            file = open('ftp.txt','w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'ftp':
                    formated = ftp_formatter(i)
                if formated:
                    file.write(formated)

        elif protocol == 'dns':
            file = open('dns.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'dns':
                    formated = dns_formatter(i)
                if formated:
                    file.write(formated)
        elif protocol == 'ips':
            file = open('ips.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'http' and ip_source == i[8] :
                    formated = http_formatter(i)
                    
                elif i[0] == 'https' and ip_source == i[8] :
                    formated = https_formatter(i)
                    
                elif i[0] == 'ftp' and ip_source == i[8] :
                    formated = ftp_formatter(i)
                    
                elif i[0] == 'smtp' and ip_source == i[8] :
                    formated = smtp_formatter(i)
                    
                elif i[0] == 'otherTCP' and ip_source == i[8] :
                    formated = otherTCP_formatter(i)
                    
                elif i[0] == 'dns' and ip_source == i[8] :
                    formated = dns_formatter(i)
                    
                elif i[0] == 'otherUDP' and ip_source == i[8] :
                    formated = otherUDP_formatter(i)

                elif i[0] == 'arp' and ip_source == i[4] :
                    formated = arp_formatter(i)
                if formated:
                    file.write(formated)

        elif protocol == 'ipd':
            file = open('ipd.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'http' and ip_destination == i[9] :
                    formated = http_formatter(i)
                    
                elif i[0] == 'https' and ip_destination == i[9] :
                    formated = https_formatter(i)
                    
                elif i[0] == 'ftp' and ip_destination == i[9] :
                    formated = ftp_formatter(i)
                    
                elif i[0] == 'smtp' and ip_destination == i[9] :
                    formated = smtp_formatter(i)
                    
                elif i[0] == 'otherTCP' and ip_destination == i[9] :
                    formated = otherTCP_formatter(i)
                    
                elif i[0] == 'dns' and ip_destination == i[9] :
                    formated = dns_formatter(i)
                    
                elif i[0] == 'otherUDP' and ip_destination == i[9] :
                    formated = otherUDP_formatter(i)

                elif i[0] == 'arp' and ip_destination == i[5] :
                    formated = arp_formatter(i)
                if formated:
                    file.write(formated)


        elif protocol == 'ipt':
            file = open('ipt.txt', 'w')
            for i in Packet_Container:
                formated = ''
                if i[0] == 'http' and ip_source == i[8] and ip_destination == i[9]:
                    formated = http_formatter(i)
                    
                elif i[0] == 'https' and ip_source == i[8] and ip_destination == i[9]:
                    formated = https_formatter(i)
                    
                elif i[0] == 'ftp' and ip_source == i[8] and ip_destination == i[9]:
                    formated = ftp_formatter(i)
                    
                elif i[0] == 'smtp' and ip_source == i[8] and ip_destination == i[9]:
                    formated = smtp_formatter(i)
                    
                elif i[0] == 'otherTCP' and ip_source == i[8] and ip_destination == i[9]:
                    formated = otherTCP_formatter(i)
                    
                elif i[0] == 'dns' and ip_source == i[8] and ip_destination == i[9]:
                    formated = dns_formatter(i)
                    
                elif i[0] == 'otherUDP' and ip_source == i[8] and ip_destination == i[9]:
                    formated = otherUDP_formatter(i)

                elif i[0] == 'arp' and ip_source == i[4] and ip_destination == i[5]:
                    formated = arp_formatter(i)
                if formated:
                    file.write(formated)




        file.close()


def http_formatter(list):
    s = ''
    s += '\n\nEthernet Frame:'
    s += '\n\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(list[1], list[2], list[3])
    s += '\n\nIPv4 Packet:'
    s += '\n\tVersion: {}, Header Length: {}, TTL: {}'.format(list[4], list[5], list[6])
    s += '\n\tProtocol: {}, Source: {}, Target: {}'.format(list[7], list[8], list[9])
    s += '\n\n\tHTTP Data:'
    s += '\n\t'+ str(list[10])
    return s
        
def https_formatter(list):
    s = ''
    s += '\n\nEthernet Frame:'
    s += '\n\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(list[1], list[2], list[3])
    s += '\n\nIPv4 Packet:'
    s += '\n\tVersion: {}, Header Length: {}, TTL: {}'.format(list[4], list[5], list[6])
    s += '\n\tProtocol: {}, Source: {}, Target: {}'.format(list[7], list[8], list[9])
    s += '\n\n\tHTTPS Data:'
    s += '\n\t'+ str(list[10])
    return s

def ftp_formatter(list):
    s = ''
    s += '\n\nEthernet Frame:'
    s += '\n\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(list[1], list[2], list[3])
    s += '\n\nIPv4 Packet:'
    s += '\n\tVersion: {}, Header Length: {}, TTL: {}'.format(list[4], list[5], list[6])
    s += '\n\tProtocol: {}, Source: {}, Target: {}'.format(list[7], list[8], list[9])
    s += '\n\n\tFTP Data:'
    s += '\n\t'+ str(list[10])
    return s

def smtp_formatter(list):
    s = ''
    s += '\n\nEthernet Frame:'
    s += '\n\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(list[1], list[2], list[3])
    s += '\n\nIPv4 Packet:'
    s += '\n\tVersion: {}, Header Length: {}, TTL: {}'.format(list[4], list[5], list[6])
    s += '\n\tProtocol: {}, Source: {}, Target: {}'.format(list[7], list[8], list[9])
    s += '\n\n\tSMTP Data:'
    s += '\n\t'+ str(list[10])
    return s

def otherTCP_formatter(list):
    s = ''
    s += '\n\nEthernet Frame:'
    s += '\n\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(list[1], list[2], list[3])
    s += '\n\nIPv4 Packet:'
    s += '\n\tVersion: {}, Header Length: {}, TTL: {}'.format(list[4], list[5], list[6])
    s += '\n\tProtocol: {}, Source: {}, Target: {}'.format(list[7], list[8], list[9])
    s += '\n\n\tother TCP Data:'
    s += '\n\t'+ str(list[10])
    return s

def dns_formatter(list):
    s = ''
    s += '\n\nEthernet Frame:'
    s += '\n\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(list[1], list[2], list[3])
    s += '\n\nIPv4 Packet:'
    s += '\n\tVersion: {}, Header Length: {}, TTL: {}'.format(list[4], list[5], list[6])
    s += '\n\tProtocol: {}, Source: {}, Target: {}'.format(list[7], list[8], list[9])
    s += '\n\n\tDNS Data:'
    s += '\n\t'+ str(list[10])
    return s

def otherUDP_formatter(list):
    s = ''
    s += '\n\nEthernet Frame:'
    s += '\n\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(list[1], list[2], list[3])
    s += '\n\nIPv4 Packet:'
    s += '\n\tVersion: {}, Header Length: {}, TTL: {}'.format(list[4], list[5], list[6])
    s += '\n\tProtocol: {}, Source: {}, Target: {}'.format(list[7], list[8], list[9])
    s += '\n\n\tother UDP Data:'
    s += '\n\t'+ str(list[10])
    return s

def arp_formatter(list):
    s = ''
    s += '\n\nEthernet Frame:'
    s += '\n\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(list[1], list[2], list[3])
    s += '\n\nARP Packet:'
    s += '\n\tSource IP: {}, Destination IP: {}'.format(list[4], list[5])
    return s


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.ntohs(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, flags = struct.unpack('! H H L L H', data[:14])
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1
    return src_port, dest_port, sequence, acknowledgment, (flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin), data[20:]

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])  # Corrected unpacking format
    return src_port, dest_port, length, data[8:]

def arp_packet(data):
    dest_mac, src_mac, eth_proto, arp_proto, arp_op, arp_src, arp_dest = struct.unpack('! 6s 6s H H H 4s 4s', data[:28])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), ipv4(arp_src), ipv4(arp_dest)

def ipv4(addr):
    return '.'.join(map(str, addr))

def ftp_decode(data):
    try:
        return data.decode('utf-8')
    except:
        return data

def http_decode(data):
    try:
        return data.decode('utf-8')
    except:
        return data

def dns_decode(data):
    dns_header = struct.unpack('! H H H H H H', data[:12])
    transaction_id = dns_header[0]
    flags = dns_header[1]
    questions = dns_header[2]
    answers = dns_header[3]
    authority_records = dns_header[4]
    additional_records = dns_header[5]

    dns_data = {
        'Transaction ID': transaction_id,
        'Flags': flags,
        'Questions': questions,
        'Answers': answers,
        'Authority Records': authority_records,
        'Additional Records': additional_records
    }

    return dns_data

def smtp_decode(data):
    try:
        return data.decode('utf-8')
    except:
        return data

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()





if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: sudo python3 file.py -all")
        print("Usage: sudo python3 file.py -tcp")
        print("Usage: sudo python3 file.py -udp")
        print("Usage: sudo python3 file.py -p <protocol>") 
        print("Usage: sudo python3 file.py -ips <ip_address>")
        print("Usage: sudo python3 file.py -ipd <ip_address>")
        print("Usage: sudo python3 file.py -ipt <ip_source_address> <ip_dest_address>")
        sys.exit(1)
    elif(len(sys.argv) == 2):
        if(sys.argv[1] == "-all"):
            main("all")
        elif(sys.argv[1] == "-tcp"):
            main("tcp")
        elif(sys.argv[1] == "-udp"):
            main("udp")
        else:
            print("Usage: sudo python3 file.py -all")
            print("Usage: sudo python3 file.py -tcp")
            print("Usage: sudo python3 file.py -udp")
            sys.exit(1)
    elif(len(sys.argv) == 3):
        if(sys.argv[1] == "-p"):
            protocol = sys.argv[2]
            main(protocol)
        elif(sys.argv[1] == "-ips"):
            ip_source = sys.argv[2]
            main("ips")
        elif(sys.argv[1] == "-ipd"):
            ip_destination = sys.argv[2]
            main("ipd")
        else:
            print("Usage: sudo python3 file.py -p <protocol>")
            print("Usage: sudo python3 file.py -ips <ip_address>")
            print("Usage: sudo python3 file.py -ipd <ip_address>")
            sys.exit(1)
    elif(len(sys.argv) == 4):
        if(sys.argv[1] == "-ipt"):
            ip_source = sys.argv[2]
            ip_destination = sys.argv[3]
            main("ipt")
        else:
            print("Usage: sudo python3 file.py -ipt <ip_source_address> <ip_dest_address>")
