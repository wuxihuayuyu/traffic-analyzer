import argparse
import sys
from collections import Counter

from rich.console import Console
from rich.table import Table
from scapy.all import IP, TCP, UDP, get_if_list, sniff

console = Console()

# IP头里的协议号是数字不是名字：6=TCP，17=UDP，1=ICMP
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# TCP标志位字母 → 全名
FLAG_NAMES = {"S": "SYN", "A": "ACK", "P": "PSH", "F": "FIN", "R": "RST", "U": "URG"}

# 同一来源触碰的不同端口数达到该值，判定为疑似扫描
SCAN_THRESHOLD = 10


def parse_flags(flags):
    names = []
    for f in str(flags):
        names.append(FLAG_NAMES.get(f, f))
    return "+".join(names)


def find_iface(keyword):
    keyword = keyword.lower()
    for iface in get_if_list():
        if keyword in iface.lower():
            return iface
    return None


class TrafficAnalyzer:
    def __init__(self):
        self.total = 0
        self.protocols = Counter()
        self.connections = Counter()
        self.no_ip = 0
        # {(源IP, 目的IP): 该来源SYN触碰过的目的端口集合}
        self.syn_ports = {}
        # 已告警的扫描来源 → 对应端口集合（引用，持续增长）
        self.scanners = {}

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
            flags = str(tcp.flags)
            print(f"{ip.src}:{tcp.sport} > {ip.dst}:{tcp.dport}  TCP  标志: {parse_flags(tcp.flags)}")

            # 端口扫描指纹：纯SYN（无ACK）打向大量不同端口
            if "S" in flags and "A" not in flags:
                ports = self.syn_ports.setdefault((ip.src, ip.dst), set())
                ports.add(tcp.dport)
                if len(ports) >= SCAN_THRESHOLD and ip.src not in self.scanners:
                    self.scanners[ip.src] = ports
                    console.print(
                        f"\n[bold red][!] 疑似端口扫描：{ip.src} 正在触碰 "
                        f"{ip.dst} 的 {len(ports)} 个不同端口[/bold red]\n"
                    )
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

        if self.scanners:
            console.print("\n[bold red]检测到疑似端口扫描：[/bold red]")
            for src, ports in self.scanners.items():
                console.print(f"  来源 {src} 在抓包期间触碰了 {len(ports)} 个不同端口")
        else:
            console.print("\n[green]未检测到端口扫描行为[/green]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Traffic Sniffer and Analyzer")
    parser.add_argument("-i", "--iface", help="监听的网卡关键词，如 loopback；默认自动选择", default=None)
    parser.add_argument("-c", "--count", type=int, default=50, help="抓包数量，默认50")
    parser.add_argument("-t", "--timeout", type=int, default=None, help="超时秒数，到时自动停止")
    args = parser.parse_args()

    iface = None
    if args.iface:
        iface = find_iface(args.iface)
        if iface is None:
            console.print(f"[red]找不到匹配 '{args.iface}' 的网卡[/red]")
            sys.exit(1)

    analyzer = TrafficAnalyzer()
    print("开始抓包...")
    sniff(iface=iface, prn=analyzer.process_packet, count=args.count, timeout=args.timeout)
    analyzer.show_report()
