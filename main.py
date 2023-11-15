from scapy.all import *
from collections import Counter
import os

INTERFACE = "wlan0"
SIGNAL_THRESHOLD = 10
DEAUTH_THRESHOLD = 10
DEAUTH_INTERVAL = 30 
 
ap_list = []
deauth_counter = Counter()
last_packet_time = 0

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

    is_evil_twin = False

    for ap in ap_list:
        if ap[0] == bssid and ap[1] == ssid and ap[3] > 1: # check if ap already exists in list
            signal_diff = abs(ap[2] - signal_strength)

            if signal_diff > SIGNAL_THRESHOLD: # check if there is a signal str difference
                print(f"Possible Evil Twin detected: {ssid} (BSSID: {bssid})")
                is_evil_twin = True
                break

    if not is_evil_twin:
        update_average_signal(ap_list, bssid, ssid, signal_strength)

    #print(ap_list, ssid , signal_strength)

def detect_deauth(packet):
    global last_packet_time

    # Check if the counter should be reset
    if packet.time - last_packet_time > DEAUTH_INTERVAL:
        deauth_counter.clear()
        last_packet_time = packet.time

    if packet.haslayer(Dot11Deauth):
        src = packet.addr2
        deauth_counter[src] += 1

        # Check if the number of deauthentication packets from a source exceeds the threshold
        if deauth_counter[src] > DEAUTH_THRESHOLD:
            print(f"Possible Deauthentication Attack Detected from {src}")

def enable_monitor_mode():
    try:
        os.system("sudo airmon-ng check kill")
        os.system(f"sudo airmon-ng start {INTERFACE}")
    except:
        print("Couldnt enable monitor mode.")
    else:
        print("Monitor mode enabled.")

def disable_monitor_mode():
    try:
        os.system(f"sudo airmon-ng stop {INTERFACE}" + "mon")
        os.system("sudo systemctl start NetworkManager")
    except:
        print("Couldnt disable monitor mode.")
    else:
        print("Monitor mode disabled.")

def scan_packets(packet):
    if packet.haslayer(Dot11):
        if packet.haslayer(Dot11Deauth): # Deauthentication packet
            detect_deauth(packet)
            
        elif packet.haslayer(Dot11Beacon): # Beacon packet
            print(packet[Dot11Elt].info.decode())
            detect_evil_twin(packet)

def sniff_packets(interface="wlan0mon"):
    sniff(iface=interface, prn=scan_packets, store=False)

if __name__ == "__main__":
    try:
        enable_monitor_mode()
        sniff_packets(INTERFACE + "mon")
    except KeyboardInterrupt:
        print("Keyboard Interrupt detected.")
        disable_monitor_mode()
