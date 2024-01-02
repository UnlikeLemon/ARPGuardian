#Work in Progress
#v1.1
from datetime import datetime
from os import system
from scapy.all import *
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-f","--file",dest="file",help="pcap(ng) FILE to be analyzed.")
parser.add_option("-i","--interface",dest="interface",help="Network interface to be utilized.")
(options,args) = parser.parse_args()

def analyze_pcap(filename):
    clients = {}
    possible_attacker = {}
    try:
        for packet in PcapReader(filename): #Read each packet in the .pcap(ng)
            if ARP in packet:
                if packet[ARP].hwsrc not in clients:
                    clients[str(packet[ARP].hwsrc)] = packet[ARP].psrc #Only read packets with ARP layer, and save each client in a dictionary.
                if packet[ARP].op == 2:
                    tx_mac = str(packet[ARP].hwsrc)
                    tx_ip = str(packet[ARP].psrc)
                    try:
                        if clients[tx_mac] != tx_ip:
                            timestamp = datetime.utcfromtimestamp(int(packet.time))
                            formatted_timestamp = timestamp.strftime("%H:%M:%S %d/%m/%Y")
                            if tx_mac in possible_attacker:
                                possible_attacker[tx_mac][1] += 1
                            else:
                                possible_attacker[tx_mac] = [clients[tx_mac], 1, formatted_timestamp, formatted_timestamp, int(packet.time), 0]
                            possible_attacker[tx_mac][3] = formatted_timestamp
                            possible_attacker[tx_mac][5] = int(packet.time)
                    except KeyError:
                        # Handle the case where tx_mac is not in clients
                        pass
    except FileNotFoundError:
        print("Cannot open file, check your spelling.")
    return possible_attacker

def calculate_timestamps(first_packet,last_packet): #Simple function to convert unix timestamps to human-readable form.
    return datetime.utcfromtimestamp(int(last_packet-first_packet)).strftime("%H:%M:%S")

def present_data(filename):
    possible_attackers = analyze_pcap(filename)
    for client, data in possible_attackers.items(): #Simply unpack the data returned from the function and print the results.
        print("Possible attackers: ")
        duration = calculate_timestamps(data[4],data[5])
        print(f"---===[{data[0]}]===---")
        print(f" User with MAC: {client} sent {data[1]} packet(s) containing `is-at` op-code\n Time since 1st packet: {data[2]}\n Last packet sent: {data[3]}\n Duration: {duration}")

def get_ip_address(mac_address): #Part of the active scanning. If a mismatch is found check the actual IP related to passed MAC, so we don't have any false positives.
    arp_req = Ether(dst=mac_address) / ARP(pdst="192.168.0.1/24",hwdst=mac_address)
    result = sr1(arp_req,timeout=3,iface=options.interface,verbose=False)
    if result and ARP in result:
        return result[ARP].psrc


clients = {}
attackers = {}
def active_scanning(packet):
    global clients,possible_attackers
    if ARP in packet:
        tx_mac = packet[ARP].hwsrc
        tx_ip = packet[ARP].psrc #Only check ARP packets, and save MAC/IP in variables
        if tx_mac not in clients:
            clients[tx_mac] = tx_ip
        if packet[ARP].op == 2:
            timestamp = datetime.utcfromtimestamp(int(packet[ARP].time))
            formated_timestamp = timestamp.strftime("%H:%M:%S | %d/%m/%Y")
            if clients[packet.src] != packet[ARP].psrc:
                print(f"{packet.src}/{clients[packet.src]} just sent a malicious `is-at` packet. | {formated_timestamp}")

def check_arguments():
    if options.interface is None and options.file is not None: #Case where we only have the -f argument
        present_data(options.file)
    elif options.interface is not None and options.file is None: #Case where we only have the -i argument
        try:
            sniff(iface=options.interface,filter="arp",prn=active_scanning,store=0)
        except OSError:
            print("Network interface doesn't exist. Check your spelling.")
    elif options.interface is not None and options.file is not None: #If both, stop the program.
        print("Conflicting arguments, use only one.")
    else:
        print("No arguments provided. Quitting....")

def main():
    system("clear")
    check_arguments()

if __name__ == "__main__":
    main()