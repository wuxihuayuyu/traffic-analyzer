from scapy.all import sniff


def handle_packet(pkt):
    print(pkt.summary())


if __name__ == "__main__":
    print("开始抓包，抓到 20 个数据包后自动停止...")
    sniff(prn=handle_packet, count=20)
    print("抓包结束")
