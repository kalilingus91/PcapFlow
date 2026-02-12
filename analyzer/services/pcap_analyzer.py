import os
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest

class PcapAnalyzer:
    def __init__(self, uploaded_file):
        self.file = uploaded_file
        self.temp_path = f"temp_{uploaded_file.name}"
        self.results = {
            'threats': [],
            'credentials': [],
            'dns_history': [],
            'http_sites': [],
            'stats': {}
        }

    def analyze(self):
        """Главный метод: сохранение, парсинг и анализ."""
        # Сохраняем файл для Scapy
        with open(self.temp_path, 'wb+') as f:
            for chunk in self.file.chunks():
                f.write(chunk)

        try:
            packets = rdpcap(self.temp_path)
            self._process(packets)
            return self.results
        finally:
            if os.path.exists(self.temp_path):
                os.remove(self.temp_path)

    def _process(self, packets):
        """Логика анализа сетевых уровней (OSI)."""
        proto_counts = Counter()
        ip_counts = Counter()
        syn_tracker = Counter()  # для детекта SYN Flood на layer4
        os_fingerprints = {}    # определение ОС на layer3

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            src_ip = pkt[IP].src
            ip_counts[src_ip] += 1
            
            # L3: OS Fingerprinting (TTL анализ) 
            ttl = pkt[IP].ttl
            os_fingerprints[src_ip] = "Linux" if ttl <= 64 else "Windows" if ttl <= 128 else "Network Device"

            # L4: Анализ протоколов и DoS
            if pkt.haslayer(TCP):
                proto_counts['TCP'] += 1
                if pkt[TCP].flags == "S": #считаем только SYN пакеты
                    syn_tracker[src_ip] += 1
                
                # детектор LDAP (на порт 389)
                if pkt[TCP].dport == 389 or pkt[TCP].sport == 389:
                    if pkt.haslayer(Raw) and b"dc=" in pkt[Raw].load.lower():
                        self._add_threat("Critical", f"LDAP Leak: Unencrypted AD traffic from {src_ip}")

            elif pkt.haslayer(UDP):
                proto_counts['UDP'] += 1
                # L7: DNS 
                if pkt.haslayer(DNSQR):
                    query = pkt[DNSQR].qname.decode(errors='ignore')
                    if query not in self.results['dns_history']:
                        self.results['dns_history'].append(query)

            # L7: HTTP и Пароли
            if pkt.haslayer(HTTPRequest):
                host = pkt[HTTPRequest].Host.decode(errors='ignore')
                if host not in self.results['http_sites']:
                    self.results['http_sites'].append(host)

            if pkt.haslayer(Raw):
                load = pkt[Raw].load.decode(errors='ignore')
                if any(word in load.upper() for word in ["PASS", "USER", "LOGIN", "PWD"]):
                    self.results['credentials'].append(f"{src_ip} -> {load.strip()[:60]}")

        # проверка на SYN Flood
        for ip, count in syn_tracker.items():
            if count > 100:
                self._add_threat("High", f"Possible SYN Flood from {ip} ({count} packets)")

        # Итоговая статистика
        self.results['stats'] = {
            'protocols': dict(proto_counts),
            'top_ips': dict(ip_counts.most_common(5)),
            'os_map': os_fingerprints,
            'total_packets': len(packets)
        }

    def _add_threat(self, severity, desc):
        threat = {'severity': severity, 'description': desc}
        if threat not in self.results['threats']:
            self.results['threats'].append(threat)


def run_pcap_analysis(file):
    return PcapAnalyzer(file).analyze()