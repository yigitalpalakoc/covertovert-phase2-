from scapy.all import IP
from scapy.all import ICMP
from scapy.all import sniff
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        super().__init__()

    def send(self, log_file_name, destination_ip, interface="eth0", inter_packet_delay=0.1):
        """
        - Create a random message, convert it to binary format, and send it by encoding each bit in the 'Don't Fragment' flag of IP packets.
        - Log the original message into the specified log file.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for bit in binary_message:
            dont_fragment = int(bit)  # 1 or 0
            packet = IP(dst=destination_ip, flags=dont_fragment) / ICMP()
            self.send(packet, interface=interface)
            self.sleep_random_time_ms(start=inter_packet_delay * 1000, end=(inter_packet_delay + 0.01) * 1000)

    def receive(self, source_ip, log_file_name):
        """
        - Listen for incoming packets, decode the message based on the 'Don't Fragment' flag in the IP header, and log the received message.
        """
        
        binary_message = ""

        def packet_handler(packet):
            nonlocal binary_message
            if packet.haslayer(IP) and packet[IP].src == source_ip:
                dont_fragment_flag = (packet[IP].flags & 0x2) >> 1
                binary_message += str(dont_fragment_flag)

        def stop_filter(packet):
            nonlocal binary_message
            return binary_message.endswith("00101110")
        
        sniff(filter=f"ip src {source_ip}", prn=packet_handler, stop_filter=stop_filter)
        decoded_message = "".join(
            self.convert_eight_bits_to_character(binary_message[i:i+8])
            for i in range(0, len(binary_message), 8)
        )

        self.log_message(decoded_message, log_file_name)
        return decoded_message
