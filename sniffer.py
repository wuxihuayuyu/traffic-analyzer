from scapy.all import sniff, IP

# IP头里的协议号是数字不是名字：6=TCP，17=UDP，1=ICMP
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def handle_packet(pkt):
    if IP in pkt:
        ip = pkt[IP]
        proto = PROTOCOLS.get(ip.proto, "其他")
        print(f"{ip.src} > {ip.dst}  协议: {proto}")
    else:
        print("(这个包没有IP层，比如ARP)")


if __name__ == "__main__":
    print("开始抓包，抓到 20 个数据包后自动停止...")
    sniff(prn=handle_packet, count=20)
    print("抓包结束")
