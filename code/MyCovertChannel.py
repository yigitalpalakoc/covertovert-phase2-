from scapy.all import IP, ICMP, sniff
from CovertChannelBase import CovertChannelBase
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def send(self, destination_ip, delay ,log_file_name):
        message_send = "msg." #TODO
        super().log_message(message_send, log_file_name)
        for letter in message_send:
            bin_letter = ord(letter)
            for i in range (0, 8):
                dont_fragment = bin_letter & 0b10000000
                dont_fragment = dont_fragment >> 6
                bin_letter = bin_letter << 1
                packet = IP(dst=destination_ip, flags=dont_fragment) / IP()
                super().send(packet, interface="eth0")
                time.sleep(delay/1000)

    def receive(self, source_ip, log_file_name):
        message_receive = ""
        msg = 0
        ctr = 0
        stop_sniffing = False
        def packet_handler(packet):
            nonlocal message_receive, msg, ctr, stop_sniffing

            if packet.haslayer(IP) and packet[IP].src == source_ip:
                # rint(f"Packet flags: {packet[IP].flags}")
                dont_fragment_flag = (packet[IP].flags & 0x2) >> 1
                msg += dont_fragment_flag
                ctr += 1
                if ctr < 8:
                    msg *= 2
                elif ctr == 8:
                    letter = chr(msg)
                    # print(msg)
                    # print(letter)
                    message_receive += letter
                    msg = 0
                    ctr = 0
                    if letter == '.':
                        stop_sniffing = True

        def stop_filter(packet):
            return stop_sniffing

        sniff(filter=f"ip src {source_ip}", prn=packet_handler, stop_filter=stop_filter)

        self.log_message(message_receive, log_file_name)

        return message_receive
