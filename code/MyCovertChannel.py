from scapy.all import IP, ICMP, sniff
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """

    def __init__(self):
        """
        Initialize the covert channel class.
        """
        super().__init__()

    def send(self, destination_ip, inter_packet_delay, log_file_name):
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        for bit in binary_message:
            dont_fragment = int(bit)  # 1 or 0
            packet = IP(dst=destination_ip, flags=dont_fragment) / ICMP()
            super().send(packet, interface="eth0")
            self.sleep_random_time_ms(start=inter_packet_delay * 1000, end=(inter_packet_delay + 0.01) * 1000)

    def receive(self, source_ip, parameter2, parameter3, log_file_name):
        """
        - Listen for incoming packets, decode the message based on the 'Don't Fragment' flag in the IP header, and log the received message.
        """
        # Initialize a variable to store the received binary message
        binary_message = ""

        def packet_handler(packet):
            nonlocal binary_message

            # Filter packets from the expected source and with an IP layer
            if packet.haslayer(IP) and packet[IP].src == source_ip:  # Assuming parameter1 is the source IP
                # Extract the 'Don't Fragment' flag (1 or 0)
                dont_fragment_flag = (packet[IP].flags & 0x2) >> 1

                # Append the extracted bit to the binary message
                binary_message += str(dont_fragment_flag)

        def stop_filter(packet):
            nonlocal binary_message
            # Check if the transmission ends (binary for '.')
            return binary_message.endswith("00101110")  # Binary for '.'

        # Capture packets until the message is fully received
        sniff(filter=f"ip src {source_ip}", prn=packet_handler, stop_filter=stop_filter)

        # Convert the binary message to a string
        decoded_message = "".join(
            self.convert_eight_bits_to_character(binary_message[i:i+8])
            for i in range(0, len(binary_message), 8)
        )

        # Log the decoded message
        self.log_message(decoded_message, log_file_name)

        return decoded_message
