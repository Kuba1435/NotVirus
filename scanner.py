from scapy.all import ARP, Ether, srp

def scan_network():
    # Prozkoumání sítě a získání informací o připojených zařízeních
    arp = ARP(pdst='192.168.1.1/24')
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    # Vypsání informací o připojených zařízeních
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("Available devices in the network:")
    print("IP" + " "*18 + "MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

# example usage
scan_network()

