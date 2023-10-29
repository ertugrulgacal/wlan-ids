from scapy.all import *

def main():
    for sniffed_packet in PcapReader("home-deauth.pcap"):
        if sniffed_packet.haslayer(Dot11):
            if sniffed_packet.type == 0 and sniffed_packet.subtype == 12:
                CheckDeauth(sniffed_packet)

def CheckDeauth(deauth_packet):
    if deauth_packet.reason == 7:
        print("Suspicious reason code (" + str(deauth_packet.reason) + ")")
    else:
        print("Normal reason code (" + str(deauth_packet.reason) + ")")

if __name__ == "__main__":
    main()