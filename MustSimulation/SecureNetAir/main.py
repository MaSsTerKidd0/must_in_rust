import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import socket
from scapy.all import rdpcap, sendp

class PacketApp(tk.Tk):
    def __init__(self, interface, pcap_file):
        super().__init__()
        self.interface = interface
        self.pcap_file = pcap_file
        self.init_ui()

    def init_ui(self):
        self.title('Packet Sender and Listener')
        self.geometry('400x300')

        self.txt_display = scrolledtext.ScrolledText(self, height=10)
        self.txt_display.pack(pady=10)

        self.btn_send_packets = tk.Button(self, text='Send Packets', command=self.send_packets)
        self.btn_send_packets.pack(pady=5)

        self.listen_thread = Thread(target=self.listen_for_udp_data, daemon=True)
        self.listen_thread.start()

    def send_packets(self):
        packets = rdpcap(self.pcap_file)
        for packet in packets:
            sendp(packet, iface=self.interface)
        self.txt_display.insert(tk.END, "Finished sending packets.\n")

    def listen_for_udp_data(self, host='127.0.0.1', port=65433):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((host, port))
            self.txt_display.insert(tk.END, f"Listening on {host}:{port} for UDP data\n")
            while True:
                data, addr = s.recvfrom(1024)
                self.txt_display.insert(tk.END, f"Received data from {addr}: {data}\n")

if __name__ == "__main__":
    # Replace 'YourNetworkInterface' with the actual interface name identified
    network_interface = 'WAN Miniport (IPv6)'  # Update this with the correct interface name
    pcap_file = 'udp_custom_packets.pcap'

    app = PacketApp(network_interface, pcap_file)
    app.mainloop()
