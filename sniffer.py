from collections import Counter

from rich.console import Console
from rich.table import Table
from scapy.all import IP, TCP, UDP, sniff

console = Console()

# IP头里的协议号是数字不是名字：6=TCP，17=UDP，1=ICMP
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# TCP标志位字母 → 全名
FLAG_NAMES = {"S": "SYN", "A": "ACK", "P": "PSH", "F": "FIN", "R": "RST", "U": "URG"}


def parse_flags(flags):
    names = []
    for f in str(flags):
        names.append(FLAG_NAMES.get(f, f))
    return "+".join(names)


class TrafficAnalyzer:
    def __init__(self):
        self.total = 0
        self.protocols = Counter()
        self.connections = Counter()
        self.no_ip = 0

    def process_packet(self, pkt):
        self.total += 1
        if IP not in pkt:
            self.no_ip += 1
            print("(无IP层，如ARP)")
            return

        ip = pkt[IP]
        if TCP in pkt:
            tcp = pkt[TCP]
            self.protocols["TCP"] += 1
            self.connections[f"{ip.src} > {ip.dst}:{tcp.dport}"] += 1
            print(f"{ip.src}:{tcp.sport} > {ip.dst}:{tcp.dport}  TCP  标志: {parse_flags(tcp.flags)}")
        elif UDP in pkt:
            udp = pkt[UDP]
            self.protocols["UDP"] += 1
            self.connections[f"{ip.src} > {ip.dst}:{udp.dport}"] += 1
            print(f"{ip.src}:{udp.sport} > {ip.dst}:{udp.dport}  UDP")
        else:
            self.protocols[PROTOCOLS.get(ip.proto, "其他")] += 1

    def show_report(self):
        console.print(f"\n[bold blue]共抓取 {self.total} 个数据包[/bold blue]")

        table = Table(show_header=True, header_style="bold green")
        table.add_column("协议", style="blue")
        table.add_column("数量", justify="center")
        table.add_column("占比", justify="center")
        for proto, count in self.protocols.most_common():
            table.add_row(proto, str(count), f"{count / self.total * 100:.1f}%")
        if self.no_ip:
            table.add_row("无IP层(ARP等)", str(self.no_ip), f"{self.no_ip / self.total * 100:.1f}%")
        console.print(table)

        console.print("\n[bold blue]通信目标 TOP 10：[/bold blue]")
        for target, count in self.connections.most_common(10):
            console.print(f"  {target}  ({count} 包)")


if __name__ == "__main__":
    analyzer = TrafficAnalyzer()
    print("开始抓包，抓到 50 个数据包后自动停止...")
    sniff(prn=analyzer.process_packet, count=50)
    analyzer.show_report()
