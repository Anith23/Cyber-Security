import socket
import struct

def sniff_packets():
    # Create a raw socket to listen for all incoming packets
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    
    # Bind the socket to the public network interface
    conn.bind(("0.0.0.0", 0))
    
    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print(f"[*] Source MAC: {src_mac}, Destination MAC: {dest_mac}, Protocol: {eth_proto}")

            # If IPv4
            if eth_proto == 8:
                version, header_length, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)
                print(f"   [+] IPv4 Packet: {src_ip} -> {dest_ip}, Protocol: {proto}")

                # If TCP
                if proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)
                    print(f"      [+] TCP Segment: {src_port} -> {dest_port}")

                # If UDP
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    print(f"      [+] UDP Segment: {src_port} -> {dest_port}")

                # If ICMP
                elif proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print(f"      [+] ICMP Packet: Type: {icmp_type}, Code: {code}")

            print("\n")

    except KeyboardInterrupt:
        print("[+] Sniffing Stopped.")

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
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src_ip), ipv4(dest_ip), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x1FF
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

if __name__ == "__main__":
    sniff_packets()
