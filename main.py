from scapy.all import *
from collections import Counter
import os
import threading
import time

INTERFACE = "wlan0"
SIGNAL_THRESHOLD = 30 
DEAUTH_THRESHOLD = 20
DEAUTH_INTERVAL = 30 
CHANNEL_HOPPING_INTERVAL = 0.5

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
            os.system(f"sudo iwconfig {INTERFACE}mon channel {channel}")
            time.sleep(CHANNEL_HOPPING_INTERVAL)

def update_average_signal(index, ap_list, signal_strength):
        ap_list[index][2] = (ap_list[index][2] * ap_list[index][4] + signal_strength) / (ap_list[index][4] + 1) # calculate new average
        ap_list[index][4] += 1

def matching_channel_number(index, ap_list, channel_number):
    if ap_list[index][3] != channel_number:
        return 1
    return -1

def rssi_difference(index, ap_list, rssi):
    if ap_list[index][4] > 20:
        rssi_diff = abs(ap_list[index][2] - rssi)

        if rssi_diff > SIGNAL_THRESHOLD:
            return 1
    return -1 

def get_ap_index(ap_list, bssid):
    for index, ap in enumerate(ap_list):
        if ap[0] == bssid:
            return index
    return -1

def detect_evil_twin(packet):
    bssid = packet[Dot11].addr3
    ssid = packet[Dot11Elt].info.decode()
    rssi = -(packet[RadioTap].dBm_AntSignal)
    channel_number = packet.channel

    if get_ap_index(ap_list, bssid) >= 0:
        ap_list_index = get_ap_index(ap_list, bssid)
    else:
        ap_list.append([bssid, ssid, rssi, channel_number, 1])
        return

    if matching_channel_number(ap_list_index, ap_list, channel_number) == 1: # Checks if the channel used corresponds to the one recorded before.
        print(f"Possible Evil Twin detected: {ssid} (BSSID: {bssid})")
        return

    if rssi_difference(ap_list_index, ap_list, rssi) == 1:
        print(f"Possible Evil Twin detected: {ssid} (BSSID: {bssid})")
        return

    update_average_signal(ap_list_index, ap_list, rssi)

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

def print_ap_list():
    for ap in ap_list:
        print(f"BSSID:{ap[0]}\tSSID:{ap[1]}\tAvg RSSI:{ap[2]:0.2f}\tChannel:{ap[3]}\tCount{ap[4]}")

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
            print(f"{packet[Dot11Elt].info.decode()}, {packet.dBm_AntSignal}")
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

        print_ap_list()

        disable_monitor_mode()
