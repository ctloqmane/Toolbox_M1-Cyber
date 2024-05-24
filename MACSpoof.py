import subprocess
import tkinter as tk
from tkinter import messagebox


class MACChangerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Changeur d'adresse MAC")
        self.geometry("400x200")
        self.setup_ui()

    def setup_ui(self):
        self.label_interface = tk.Label(self, text="Interface réseau:")
        self.label_interface.pack(pady=5)

        self.entry_interface = tk.Entry(self, width=30)
        self.entry_interface.pack()

        self.label_mac = tk.Label(self, text="Nouvelle adresse MAC:")
        self.label_mac.pack(pady=5)

        self.entry_mac = tk.Entry(self, width=30)
        self.entry_mac.pack()

        self.change_button = tk.Button(self, text="Changer l'adresse MAC", command=self.change_mac_address)
        self.change_button.pack(pady=10)

    def change_mac_address(self):
        interface = self.entry_interface.get()
        new_mac = self.entry_mac.get()

        if not interface or not new_mac:
            messagebox.showwarning("Avertissement", "Veuillez entrer l'interface réseau et la nouvelle adresse MAC.")
            return

        try:
            self.run_command(["ifconfig", interface, "down"])
            self.run_command(["ifconfig", interface, "hw", "ether", new_mac])
            self.run_command(["ifconfig", interface, "up"])
            messagebox.showinfo("Succès", f"L'adresse MAC de {interface} a été changée en {new_mac}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur s'est produite : {str(e)}")

    def run_command(self, command):
        subprocess.run(command, check=True)


if __name__ == "__main__":
    app = MACChangerApp()
    app.mainloop()
