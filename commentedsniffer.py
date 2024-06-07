import socket
import struct
import textwrap

def main():#this function will capture the network traffic and specifies the data the sender the reciever and other etails esecially for ipv4 (udp, tcp and icmp)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #create a socket object that can capture all ipv4 packets (socket.ntohs(3)) on the network layer  (socket.SOC_RAW)
    while True:
        captured_data, addr =conn.recvfrom(65536) #receive data from the socket it returns the data and a tuple (addr) contains the the sender's ip @ and num port the data has a maximum size 65536 which is a common maximum size for network packets
        d_add_mac, s_add_mac, prtcl , data = ethernet_frame(captured_data) #extracting info based in the format of ethernet packet
        print('\n Ethernet Frame:')
        print('\t '+ 'MAC Destination: {}, MAC Source {}, Protocol: {}'.format(d_add_mac, s_add_mac, prtcl)) 
        #based on the val of protocol now we're gonna extract ata adresses of reciever and sender 
        if prtcl == 8: #in case it is ipv4
            (version,IHL,ttl, protocol, src, des, data) = ipv4_packet(data)
            print('\t ' + 'IPv4 Packet:')
            print('\t\t ' + 'varsion: {}, header length: {} , TTL: {}'.format(version, IHL , ttl))
            print('\t\t ' + 'protocol: {}, source address: {}, Destination address: {}'.format(protocol, src, des))
            if protocol == 1 : #in case it is icmp
                type, code, checksum, data = icmp_packet(data)
                print('\t ' + 'ICMP Packet:')
                print('\t\t '  + 'Type: {}, code: {}, ICMP Checksome: {}'.format(type, code, checksum))
                print('\t\t '  + 'DATA :')
                print(format_multi_line('\t\t\t\t\t ' , data))
            elif protocol == 6: #case it is tcp
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segmant(data)
                print('\t ' + 'TCP Segment:')
                print('\t\t '  + 'Source port : {}, Destination port : {}'.format(src_port, dest_port))
                print('\t\t ' + 'sequence Number:{}, acknowledgment Number : {}'.format(sequence,acknowledgment))
                print('\t\t '  + 'Flags :')
                print('\t\t\t '  + 'URG : {}, ACK : {}, PSH: {},RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('\t\t '  + 'data :')
                print ( format_multi_line('\t\t\t\t\t ' , data))
            elif protocol == 17: #case it is udp
                src_port, dest_port, length, data = udp_segment(data)
                print('\t ' + 'UDP Segment:')
                print('\t\t ' + 'Source Port : {} , Destination Port : {}, Length {}'.format(src_port, dest_port, length))
            #others
            else : # other then udp tcp and icmp (in most cases it is one of those)
                print( '\t ' + 'Data:')
                print(format_multi_line('\t\t ', data))
        else : #in case it's not ipv4
            print ('Data:')
            print(format_multi_line('\t ', data))


# Unpack ethernet frame
def ethernet_frame(data):
    d_add_mac, s_add_mac ,prtcl = struct.unpack('! 6s 6s H', data[:14]) #struct.unpack : unpacks binary data according to a specified format string 
    # '!' : this specifies that the data should be interpreted in big-endian byte order
    # '6s' : string = 6 bytes
    # 'H' : specifies an unsigned short integer (2 bytes)
    return get_mac_addr(d_add_mac), get_mac_addr(s_add_mac), socket.htons(prtcl), data[14:]
    # socket.htons(proto) function call is used to convert a 16-bit integer from host byte order to network byte order.
def get_mac_addr(adresse_by):
    adresse_by = map('{:02x}'.format,adresse_by)
    # '{:02x}' specifies that an integer should be formatted as a hexadecimal string with at least two characters, zero-padded if necessary.
    # map(function, iterable) :  applies a specified function to each item in an iterable (such as a list, tuple, or string) and returns an iterator that yields the results. 
    mac_add=':'.join(adresse_by).upper()
    return mac_add
#unpack ipv4 packet
def ipv4_packet(data):
    version_IHL= data[0]
    version = version_IHL>> 4 #>>: This is the right shift bitwise operator. It shifts the bits of a binary value to the right by a specified number of positions.
    IHL = (version_IHL & 15) * 4
    # & 15: This is a bitwise AND operation with 15, which is 1111 in binary. Performing a bitwise AND with 15 effectively masks out the version bits, leaving only the 4 bits representing the header length.
    # * 4: After extracting the header length bits, this expression multiplies the result by 4. In IPv4, the header length field represents the number of 32-bit words in the header, so multiplying by 4 converts it to the number of bytes
    ttl, protocol, src, des = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    # 8x: Skips 8 bytes in the data. This is often used to skip over fields in the header that are not of interest.
    # B B: Unpacks two unsigned bytes (each 1 byte in size) from the data.
    # 2x: Skips 2 bytes in the data.
    # 4s: Unpacks a string of length 4 bytes.
    return version,IHL,ttl,protocol,ipv4(src),ipv4(des),data[IHL:]
# returns properly formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str,addr))
# unpacks icmp packet
def icmp_packet(data):
    type, code, checksum = struct.unpack('! B B H', data[:4])
    return type, code, checksum , data[4:]
def tcp_segmant(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',data[:14])
    # L: Unsigned long integer (4 bytes).
    Data_offset = (offset_reserved_flags >> 12)*4 #The "data offset" field in a TCP header specifies the size of the TCP header in 32-bit words(*4 gives us en bits). It indicates the beginning of the data section or the start of the payload within the TCP segment.
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