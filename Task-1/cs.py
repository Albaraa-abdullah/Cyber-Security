import socket
import struct
import textwrap

T_1 = '\t -'
T_2 = '\t\t -'
T_3 = '\t\t\t -'
T_4 = '\t\t\t\t -'
D_T_1 = '\t '
D_T_2 = '\t\t '
D_T_3 = '\t\t\t '
D_T_4 = '\t\t\t\t '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEtheret Frame: ')
        print(T_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            (version, header_length, TTL, proto, src, target, data) = ipv4_packet(data)
            print(T_1 + 'IPV4 Packet:')
            print(T_2 + 'Version: {}, Header Lenght: {}, TTL: {}'.format(version, header_length, TTL))
            print(T_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(T_1 + 'IPV4 Packet:')
                print(T_2 + 'Type: {}, Code: {}, Check Sum: {}'.format(icmp_type, code, checksum))
                print(T_2 + 'Data:')
                print(format_multi_line(D_T_3, data))

            elif proto == 6:
                (src_pot, dest_port, sequence, acknowledgemet, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(T_1 + 'TCP Segment:')
                print(T_2 + 'Source Port: {}, Distination Port: {}'.format(src_pot, dest_port))
                print(T_2 + 'Sequence: {}, Acknowledgemet: {}'.format(sequence, acknowledgemet))
                print(T_2 + 'Flags:')
                print(T_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(T_2 + 'Data:')
                print(format_multi_line(D_T_3, data))

            elif proto == 17:
                src_pot, dest_port, length, data = udp_segment(data)
                print(T_1 + 'UDP Segment:')
                print(T_2 + 'Source Port: {}, Distination Port: {}, Length: {}'.format(src_pot, dest_port, length))

            else:
               print(T_1 + 'Data:') 
               print(format_multi_line(D_T_2, data))
        else:
            print(T_1 + 'Data:') 
            print(format_multi_line(D_T_1, data))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4 
    TTL, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, TTL, proto, ipv4(src), ipv4(target), data[header_length:] 

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_pot, dest_port, sequence, acknowledgemet, offset_rserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_rserved_flags >> 12) *4 
    flag_urg = (offset_rserved_flags & 32) >> 5
    flag_ack = (offset_rserved_flags & 16) >> 4
    flag_psh = (offset_rserved_flags & 8) >> 3
    flag_rst = (offset_rserved_flags & 4) >> 2
    flag_syn = (offset_rserved_flags & 2) >> 1
    flag_fin = offset_rserved_flags & 1
    return src_pot, dest_port, sequence, acknowledgemet, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix)        
    #return '\n'.join(prefix +  line for line in textwarp.warp(string, size))

