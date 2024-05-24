# Toolbox - M1 Cybersécurité

## Fonctionnalités

- **Bruteforce SSH** : Tente de se connecter à un serveur SSH en utilisant une liste de noms d'utilisateur et de mots de passe.
- **Scanner ARP** : Scanne une plage d'adresses IP pour identifier les périphériques connectés au réseau.
- **Scan MAC** : Scanne les adresses MAC des dispositifs connectés à un réseau local.
- **Spoof MAC** : Usurpe l'adresse MAC des dispositifs scannés.
- **Scanner de vulnérabilités web** : Scanne un site web pour des vulnérabilités courantes comme les injections SQL et le XSS.
- **Scanner Nmap** : Utilise Nmap pour scanner les ports d'une adresse IP ou d'un réseau.

## Installation

Pour exécuter ce projet, vous devez installer les bibliothèques Python suivantes :

1. `tkinter` : Pour créer l'interface graphique (généralement inclus avec Python).
2. `pynput` : Pour surveiller les frappes de touches.
3. `requests` : Pour envoyer des requêtes HTTP.
4. `paramiko` : Pour les connexions SSH.
5. `scapy` : Pour envoyer des requêtes ARP.
6. `tqdm` : Pour afficher une barre de progression.
7. `pillow` : Pour certaines fonctionnalités graphiques avancées dans tkinter.
8. `keyboard` : Pour écouter et enregistrer les événements du clavier.
9. `beautifulsoup4` : Pour parser le HTML des pages web.
10. `python-nmap` : Pour utiliser Nmap via Python.

### Installation des dépendances

Vous pouvez installer toutes les dépendances en utilisant les commandes `pip` suivantes :

```bash
pip install pynput
pip install requests
pip install paramiko
pip install scapy
pip install tqdm
pip install pillow
pip install keyboard
pip install beautifulsoup4
pip install python-nmap
