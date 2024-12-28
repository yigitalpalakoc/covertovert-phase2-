# Covert Storage Channel that exploits Protocol Field Manipulation using Don't Fragment Flag field in IP [Code: CSC-PSV-IP-DFF]

This simple Covert channel example aims to manipulate the **"DF" (Don't Fragment) Flag** on the IP Packet's "Flags" register. Since the "DF Flag" is the second bit of the 3-bit Flags register, we should set the Flags register as "000" or "010" depending on the bit to be transmitted via the channel.

## Send Function:

The send function is quite trivial.First it generates a random human-readable string with a single dot at the end. Then wwe take the length of the string for diagnostics purposes as we also need to calculate the speed of our function in **packets (bits in this case) per second**. The created message is then logged for further reference as wew may need this info for further debugging. Then, the timer is started for calculating delta time for our speed calculations.

The for loops of this functions are its main parts where each char is first casted into unsigned integers and then packaged and sent bit by bit. In order for us to place the bits accordingly however, we first take the MSB of the first char and use the **logical and operator** to extract the MSB of the char. Then we first right shift the extracted MSB seven times to get a single bit, which will be then left shifted once to place the extracted bit on the second fit of the Flags register. I chose to just right shift the result six times for convenience. Then we left shift the char once to get the next bit, create a packet with the previously extracted bit on the "DF Flag", send the said packet, rinse and repeat for each bit of each char of the created message. Only extra in this code is i have added a delay of 1ms afther each sent packet just in case. Finally, when all the packets are sent, we stop the timer, calculate the delta and print a message showing how many packets(bits in this case) were sent in a second.

## Receive Function:

The receive function is also quite trivial. First it initializes an empty string for the chars extracted from the packets, then we initialize a message integer which will be used for accumulating the bits of the chars as integers and the a counter for counting the number of packets for casting the accumulated message into chars each time we hit the eighth packet, which means that a byte of information was captured. The "stop_sniffing" flag is used for creating a very primitive stop filter for the sniff function.

The packet handler is the main part of our receive function. Packet handler has access to every variable necessary in the scope of the recevive function. The handler first filters packets with IP layers and IP values equal to predetermined source IP. Then we extract the "DF Flag" from the flags. Then we add the value of the flag to the message accumulator and increase the packet counter by 1. Then, if the packet counter is less than 8, which means that the transmitted char is not transmissed completely yet, we left shift the message accumulator once to prepare the accumulator for the next bit. If the packet counter is equal to 8, meaning the char is transmitted completely, we take the message accumulator and cast its value into a char and push that char into the string "message_received". The mesage accumulator and the packet counters are reset to 0. Lastly, we check if the char received was a dot (.) or not. If the char received was a dot (.), we set the "stop_sniffing" flag, stopping our sniff function.

Lastly, we log the received message for further debugging and return the message.

