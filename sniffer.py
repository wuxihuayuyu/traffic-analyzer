import argparse
import json
import sys
import time
from collections import Counter, deque

from rich.console import Console
from rich.table import Table
from scapy.all import IP, TCP, UDP, get_if_list, sniff

console = Console()

# IP头里的协议号是数字不是名字：6=TCP，17=UDP，1=ICMP
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# TCP标志位字母 → 全名
FLAG_NAMES = {"S": "SYN", "A": "ACK", "P": "PSH", "F": "FIN", "R": "RST", "U": "URG"}

# 窗口时间内同一来源触碰的不同端口数达到该值，判定为疑似扫描
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


class ScanTracker:
    """滑动时间窗口内统计每个来源触碰过的不同端口，超阈值就告警一次"""

    def __init__(self, window, label):
        self.window = window
        self.label = label
        # {(源IP, 目的IP): deque([(时间戳, 端口), ...])}，只留窗口内的记录
        self.touches = {}
        # 触发过的告警事件，最后写进报告
        self.alerts = []

    def touch(self, src, dst, port):
        now = time.time()
        hits = self.touches.setdefault((src, dst), deque())
        hits.append((now, port))

        # 新包来了先把窗口外的旧记录挤出去，再数剩下的
        while hits and now - hits[0][0] > self.window:
            hits.popleft()

        distinct = {port for _, port in hits}
        if len(distinct) >= SCAN_THRESHOLD:
            span = round(now - hits[0][0], 1)
            self.alerts.append({
                "src": src,
                "dst": dst,
                "distinct_ports": len(distinct),
                "within_seconds": span,
            })
            console.print(
                f"\n[bold red][!] 疑似{self.label}扫描：{src} 在 {span} 秒内触碰了 "
                f"{dst} 的 {len(distinct)} 个不同端口[/bold red]\n"
            )
            # 清空重新计数，同一波扫描不重复刷屏
            hits.clear()


class TrafficAnalyzer:
    def __init__(self, window):
        self.total = 0
        self.protocols = Counter()
        self.connections = Counter()
        self.no_ip = 0
        # TCP 和 UDP 分开跟踪，指纹不一样
        self.syn_tracker = ScanTracker(window, "TCP SYN")
        self.udp_tracker = ScanTracker(window, "UDP")

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
                self.syn_tracker.touch(ip.src, ip.dst, tcp.dport)
        elif UDP in pkt:
            udp = pkt[UDP]
            self.protocols["UDP"] += 1
            self.connections[f"{ip.src} > {ip.dst}:{udp.dport}"] += 1
            print(f"{ip.src}:{udp.sport} > {ip.dst}:{udp.dport}  UDP")
            # UDP没有握手，只能按短时间触碰大量不同端口来判
            self.udp_tracker.touch(ip.src, ip.dst, udp.dport)
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

        report = {
            "total_packets": self.total,
            "protocols": dict(self.protocols),
            "no_ip_packets": self.no_ip,
            "top_connections": [
                {"target": t, "packets": c} for t, c in self.connections.most_common(10)
            ],
            "tcp_syn_scan_alerts": self.syn_tracker.alerts,
            "udp_scan_alerts": self.udp_tracker.alerts,
        }

        alerts = self.syn_tracker.alerts + self.udp_tracker.alerts
        if alerts:
            console.print("\n[bold red]检测到疑似端口扫描：[/bold red]")
            for a in alerts:
                console.print(
                    f"  来源 {a['src']} 在 {a['within_seconds']} 秒内触碰了 "
                    f"{a['dst']} 的 {a['distinct_ports']} 个不同端口"
                )
        else:
            console.print("\n[green]未检测到端口扫描行为[/green]")

        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Traffic Sniffer and Analyzer")
    parser.add_argument("-i", "--iface", help="监听的网卡关键词，如 loopback；默认自动选择", default=None)
    parser.add_argument("-c", "--count", type=int, default=50, help="抓包数量，默认50")
    parser.add_argument("-t", "--timeout", type=int, default=None, help="超时秒数，到时自动停止")
    parser.add_argument("-w", "--window", type=int, default=10, help="扫描检测的时间窗口秒数，默认10")
    parser.add_argument("-o", "--output", help="把统计报告导出成 JSON 文件，如 report.json", default=None)
    args = parser.parse_args()

    iface = None
    if args.iface:
        iface = find_iface(args.iface)
        if iface is None:
            console.print(f"[red]找不到匹配 '{args.iface}' 的网卡[/red]")
            sys.exit(1)

    analyzer = TrafficAnalyzer(window=args.window)
    print("开始抓包...")
    sniff(iface=iface, prn=analyzer.process_packet, count=args.count, timeout=args.timeout)
    report = analyzer.show_report()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        console.print(f"\n[bold blue]报告已导出到 {args.output}[/bold blue]")
