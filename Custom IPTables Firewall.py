import subprocess
from scapy.all import *

blocked_ips = ["192.168.1.100", "10.0.0.5"]
blocked_ports = [80, 443]

def setup_iptables():
    subprocess.run("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", shell=True)

    subprocess.run("iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT", shell=True)

    subprocess.run("iptables -A INPUT -j LOG --log-prefix 'IPTables-Dropped: '", shell=True)

    subprocess.run("iptables -A INPUT -p tcp --dport 22 -j ACCEPT", shell=True)

    subprocess.run("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE", shell=True)
    
    subprocess.run("ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", shell=True)

    subprocess.run("iptables -A INPUT -p tcp --dport 80 -m limit --limit 10/min -j ACCEPT", shell=True)


def add_iptables_rule(ip=None, port=None):

    cmd = "iptables -A INPUT"
    if ip:
        cmd += f" -s {ip} -j DROP"
    elif port:
        cmd += f" --dport {port} -j DROP"
    subprocess.run(cmd, shell=True)

def packet_callback(packet):

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if src_ip in blocked_ips or dst_ip in blocked_ips:
            add_iptables_rule(ip=src_ip)
            return

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        sport = packet.sport
        dport = packet.dport
        if sport in blocked_ports or dport in blocked_ports:
            add_iptables_rule(port=dport)
            return

setup_iptables()

sniff(prn=packet_callback, store=0)
