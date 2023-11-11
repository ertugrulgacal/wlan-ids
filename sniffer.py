from scapy.all import *
from collections import Counter

SIGNAL_THRESHOLD = 10
 
ap_list = []

def update_average_signal(ap_list, bssid, ssid, signal_strength):
    for ap in ap_list:
        if ap[0] == bssid and ap[1] == ssid:
            ap[2] = (ap[2] * ap[3] + signal_strength) / (ap[3] + 1) # calculate new average
            ap[3] += 1
            return
    # If AP is not in the list, add it with the initial signal strength
    ap_list.append([bssid, ssid, signal_strength, 1])

def detect_evil_twin(packet):
    bssid = packet[Dot11].addr3
    ssid = packet[Dot11Elt].info.decode()
    signal_strength = -(packet[RadioTap].dBm_AntSignal)

    update_average_signal(ap_list, bssid, ssid, signal_strength)

    for ap in ap_list:
        if ap[0] == bssid and ap[1] == ssid and ap[3] > 1: # check if ap already exists in list
            signal_diff = abs(ap[2] - signal_strength)
            if signal_diff > SIGNAL_THRESHOLD: # check if there is a signal str difference
                print(f"Possible Evil Twin detected: {ssid} (BSSID: {bssid})")
            return

def scan_packets(packet):
    if packet.haslayer(Dot11):
        if packet.haslayer(Dot11Deauth): # Deauthentication packet
            pass
        elif packet.haslayer(Dot11Beacon): # Beacon packet
            detect_evil_twin(packet)

def sniff_packets(interface="wlan0mon"):
    sniff(iface=interface, prn=scan_packets, store=False)

if __name__ == "__main__":
    sniff_packets("wlan0mon")
