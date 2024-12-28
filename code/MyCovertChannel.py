from scapy.all import IP, sniff
from CovertChannelBase import CovertChannelBase
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        self.key = "M3t0C3ng" # Encryption key

    def send(self, destination_ip, delay, log_file_name):
        message_send = super().generate_random_message()
        len_msg = len(message_send)
        key_len = len(self.key)
        enc_msg = bytearray(message_send.encode())
        
        super().log_message(message_send, log_file_name)

        # Encrypt the message
        for i in range(len_msg):
            enc_msg[i] = enc_msg[i] ^ ord(self.key[i % key_len])
        
        start = time.time()
        for byte in enc_msg:
            bin_letter = byte
            for i in range(8):
                flag = bin_letter & 0b10000000
                flag = flag >> 6
                bin_letter = bin_letter << 1
                packet = IP(dst=destination_ip, flags=flag) / IP()
                super().send(packet, interface="eth0")
                time.sleep(delay / 1000)
        end = time.time()
        length = end - start
        print(len_msg * 8, "packets in", length, "seconds, avg =", (len_msg * 8) / length, "packets (bits) / second.")

    def receive(self, source_ip, log_file_name):
        message_receive = b""
        msg = 0
        ctr = 0
        stop_sniffing = False
        curr_index = 0
        key_len = len(self.key)

        def packet_handler(packet):
            nonlocal message_receive, msg, ctr, stop_sniffing, curr_index
            
            if packet.haslayer(IP) and packet[IP].src == source_ip:
                print(f"Packet flags: {packet[IP].flags}")
                dont_fragment_flag = (packet[IP].flags & 0x2) >> 1
                msg += dont_fragment_flag
                ctr += 1
                if ctr < 8:
                    msg *= 2
                elif ctr == 8:
                    #Decrypt the message
                    message_receive += bytes([msg ^ ord(self.key[curr_index % key_len])])
                    curr_index += 1
                    msg = 0
                    ctr = 0
                    if message_receive.endswith(b"."):
                        stop_sniffing = True

        def stop_filter(packet):
            return stop_sniffing

        sniff(filter=f"ip src {source_ip}", prn=packet_handler, stop_filter=stop_filter)

        self.log_message(message_receive.decode(), log_file_name)

        return message_receive