import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import threading
import subprocess

class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
        self.geometry("600x400")
        self.configure(bg='#f0f0f0')

        self.create_widgets()
        self.scan_thread = None

    def create_widgets(self):
        # Frame pour les informations de la cible
        target_frame = ttk.LabelFrame(self, text="Informations de la cible", padding=(10, 5))
        target_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        ttk.Label(target_frame, text="Adresse IP de la cible :").grid(column=0, row=0, padx=5, pady=5, sticky="w")
        self.entry_ip = ttk.Entry(target_frame)
        self.entry_ip.grid(column=1, row=0, padx=5, pady=5)

        ttk.Label(target_frame, text="Plage de ports (de - à) :").grid(column=2, row=0, padx=5, pady=5, sticky="w")
        self.entry_start_port = ttk.Entry(target_frame, width=10)
        self.entry_start_port.grid(column=3, row=0, padx=5, pady=5, sticky="w")
        self.entry_end_port = ttk.Entry(target_frame, width=10)
        self.entry_end_port.grid(column=4, row=0, padx=5, pady=5, sticky="w")

        # Frame pour les options de scan
        options_frame = ttk.LabelFrame(self, text="Options de scan", padding=(10, 5))
        options_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        self.scan_type = tk.StringVar()
        self.scan_type.set("tcp")

        ttk.Radiobutton(options_frame, text="Scan TCP Connect (-sT)", variable=self.scan_type, value="tcp").grid(column=0, row=0, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(options_frame, text="Scan UDP (-sU)", variable=self.scan_type, value="udp").grid(column=1, row=0, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(options_frame, text="Scan Intense (-T4)", variable=self.scan_type, value="intense").grid(column=2, row=0, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(options_frame, text="Scan rapide (-F)", variable=self.scan_type, value="fast").grid(column=3, row=0, padx=5, pady=5, sticky="w")

        # Bouton pour démarrer le scan
        self.btn_scan = ttk.Button(self, text="Démarrer le scan", command=self.start_scan)
        self.btn_scan.grid(row=2, column=0, pady=10)

        # Zone de texte déroulante pour afficher les résultats
        result_frame = ttk.LabelFrame(self, text="Résultats du scan", padding=(10, 5))
        result_frame.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=70, height=15)
        self.result_text.grid(column=0, row=0, padx=5, pady=5)

        # Configure the column and row weights
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

    def start_scan(self):
        target_ip = self.entry_ip.get()
        start_port = self.entry_start_port.get()
        end_port = self.entry_end_port.get()

        if not target_ip or not start_port or not end_port:
            self.result_text.insert(tk.END, "Veuillez saisir une adresse IP cible et une plage de ports.\n")
            return

        try:
            start_port = int(start_port)
            end_port = int(end_port)
        except ValueError:
            self.result_text.insert(tk.END, "Veuillez saisir des numéros de port valides.\n")
            return

        if start_port > end_port:
            self.result_text.insert(tk.END, "Le port de début doit être inférieur ou égal au port de fin.\n")
            return

        nmap_cmd = "nmap"
        scan_option = self.scan_type.get()
        if scan_option == "tcp":
            nmap_cmd += " -sT"
        elif scan_option == "udp":
            nmap_cmd += " -sU"
        elif scan_option == "intense":
            nmap_cmd += " -T4"
        elif scan_option == "fast":
            nmap_cmd += " -F"
        nmap_cmd += f" -p {start_port}-{end_port} {target_ip}"

        self.result_text.insert(tk.END, f"Balayage de ports sur {target_ip}...\n")

        self.scan_thread = threading.Thread(target=self.run_nmap, args=(nmap_cmd,))
        self.scan_thread.start()

    def run_nmap(self, nmap_cmd):
        try:
            output = subprocess.check_output(nmap_cmd, shell=True, universal_newlines=True)
            self.result_text.insert(tk.END, output)
        except subprocess.CalledProcessError as e:
            self.result_text.insert(tk.END, f"Erreur lors de l'exécution de la commande Nmap : {e.output}\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Erreur inattendue : {e}\n")


if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()
