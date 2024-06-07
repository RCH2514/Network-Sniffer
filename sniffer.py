
import socket
import struct
import textwrap

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) 
    while True:
        captured_data, addr =conn.recvfrom(65536) 
        d_add_mac, s_add_mac, prtcl , data = ethernet_frame(captured_data) 
        print('\n Ethernet Frame:')
        print('\t '+ 'MAC Destination: {}, MAC Source {}, Protocol: {}'.format(d_add_mac, s_add_mac, prtcl)) 
        
        if prtcl == 8: 
            (version,IHL,ttl, protocol, src, des, data) = ipv4_packet(data)
            print('\t ' + 'IPv4 Packet:')
            print('\t\t ' + 'varsion: {}, header length: {} , TTL: {}'.format(version, IHL , ttl))
            print('\t\t ' + 'protocol: {}, source address: {}, Destination address: {}'.format(protocol, src, des))
            if protocol == 1 : 
                type, code, checksum, data = icmp_packet(data)
                print('\t ' + 'ICMP Packet:')
                print('\t\t '  + 'Type: {}, code: {}, ICMP Checksome: {}'.format(type, code, checksum))
                print('\t\t '  + 'DATA :')
                print(format_multi_line('\t\t\t\t\t ' , data))
            elif protocol == 6: 
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segmant(data)
                print('\t ' + 'TCP Segment:')
                print('\t\t '  + 'Source port : {}, Destination port : {}'.format(src_port, dest_port))
                print('\t\t ' + 'sequence Number:{}, acknowledgment Number : {}'.format(sequence,acknowledgment))
                print('\t\t '  + 'Flags :')
                print('\t\t\t '  + 'URG : {}, ACK : {}, PSH: {},RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('\t\t '  + 'data :')
                print ( format_multi_line('\t\t\t\t\t ' , data))
            elif protocol == 17: 
                src_port, dest_port, length, data = udp_segment(data)
                print('\t ' + 'UDP Segment:')
                print('\t\t ' + 'Source Port : {} , Destination Port : {}, Length {}'.format(src_port, dest_port, length))
            
            else : 
                print( '\t ' + 'Data:')
                print(format_multi_line('\t\t ', data))
        else : 
            print ('Data:')
            print(format_multi_line('\t ', data))



def ethernet_frame(data):
    d_add_mac, s_add_mac ,prtcl = struct.unpack('! 6s 6s H', data[:14])  
    return get_mac_addr(d_add_mac), get_mac_addr(s_add_mac), socket.htons(prtcl), data[14:]
def get_mac_addr(adresse_by):
    adresse_by = map('{:02x}'.format,adresse_by)
    mac_add=':'.join(adresse_by).upper()
    return mac_add

def ipv4_packet(data):
    version_IHL= data[0]
    version = version_IHL>> 4 
    IHL = (version_IHL & 15) * 4
    ttl, protocol, src, des = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version,IHL,ttl,protocol,ipv4(src),ipv4(des),data[IHL:]
def ipv4(addr):
    return '.'.join(map(str,addr))
def icmp_packet(data):
    type, code, checksum = struct.unpack('! B B H', data[:4])
    return type, code, checksum , data[4:]
def tcp_segmant(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',data[:14])
    Data_offset = (offset_reserved_flags >> 12)*4 
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack= (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8 ) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[Data_offset:]
def udp_segment(data):
    src_port, dest_port,size = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, size,data[8:]
def format_multi_line(prefix,string,size=80):
    size -= len (prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
#
#
#
#
#
main()