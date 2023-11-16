from scapy.all import *
from collections import Counter
import os
import threading
import time

INTERFACE = "wlan0"
SIGNAL_THRESHOLD = 10 
DEAUTH_THRESHOLD = 10
DEAUTH_INTERVAL = 30 
 
ap_list = []
deauth_counter = Counter()
last_packet_time = 0
stop_event = threading.Event()

def channel_hopper():
    channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    while not stop_event.is_set(): 
        for channel in channels:
            if stop_event.is_set():
                break
            os.system(f"iwconfig {INTERFACE}mon channel {channel}")
            time.sleep(1)

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
        if ap[0] == bssid and ap[1] == ssid and ap[3] > 20: # check if ap already exists in list
            signal_diff = abs(ap[2] - signal_strength)

            if signal_diff > SIGNAL_THRESHOLD: # check if there is a signal str difference
                print(f"Possible Evil Twin detected: {ssid} (BSSID: {bssid})")
                is_evil_twin = True
                break

    if not is_evil_twin:
        update_average_signal(ap_list, bssid, ssid, signal_strength)

    #print(len(ap_list))
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
            detect_evil_twin(packet)

def sniff_in_thread(interface, stop_event):
    try:
        sniff(iface=interface, prn=scan_packets, store=False, stop_filter=lambda x: stop_event.is_set())
    except Exception as e:
        print("Sniffing error:", e)

if __name__ == "__main__":
    try:
        enable_monitor_mode()
        hopper_thread = threading.Thread(target=channel_hopper)
        sniffer_thread = threading.Thread(target=sniff_in_thread, args=(INTERFACE+"mon", stop_event))
        
        hopper_thread.daemon = True
        sniffer_thread.daemon = True

        hopper_thread.start()
        sniffer_thread.start()
        
        # Wait for threads to complete or KeyboardInterrupt
        while hopper_thread.is_alive() and sniffer_thread.is_alive():
            time.sleep(1)

    except KeyboardInterrupt:
        print("Keyboard Interrupt detected.")
        stop_event.set()  # Signal threads to stop

        hopper_thread.join()
        sniffer_thread.join()

        print(ap_list)

        disable_monitor_mode()
