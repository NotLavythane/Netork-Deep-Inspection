#!/usr/bin/env python3
# Deep Network Forensics Tool - Windows Application-Aware Edition
# Filename: forensics_tool.py

import json
import time
import socket
import struct
import threading
import queue
from datetime import datetime
from collections import defaultdict, Counter, deque
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict, field
import hashlib
import os
import sys
import platform
import ctypes
import argparse
import csv
from pathlib import Path
import warnings
import subprocess

warnings.filterwarnings('ignore')

# Platform detection
IS_WINDOWS = platform.system() == "Windows"

# Windows-specific imports
if IS_WINDOWS:
    try:
        import winreg
        WINDOWS_DEEP_INSPECTION = True
    except ImportError:
        WINDOWS_DEEP_INSPECTION = False
else:
    WINDOWS_DEEP_INSPECTION = False

__version__ = "3.0.1-Deep"
__author__ = "Cyber Forensics Team"

def is_admin():
    """Check administrator privileges"""
    try:
        if IS_WINDOWS:
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False

def run_as_admin():
    """Re-run script as administrator"""
    if IS_WINDOWS and not is_admin():
        print("[!] Requesting administrator privileges...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def check_npcap():
    """Check if Npcap is installed (Windows only)"""
    if not IS_WINDOWS:
        return True, "Linux/Mac"
    
    npcap_paths = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll"
    ]
    
    for path in npcap_paths:
        if os.path.exists(path):
            return True, path
    
    # Check registry
    try:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap") as key:
                return True, "Registry"
        except:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap") as key:
                return True, "Registry (WOW64)"
    except:
        pass
    
    return False, None

# Scapy configuration
try:
    if IS_WINDOWS:
        import scapy.config
        scapy.config.conf.use_pcap = True
        scapy.config.conf.use_npcap = True
    
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, 
        conf, rdpcap, get_if_list
    )
    if IS_WINDOWS:
        from scapy.arch.windows import get_windows_if_list
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"ERROR: Scapy not installed. Run: pip install scapy")

try:
    from flask import Flask, render_template_string, jsonify, request
    from flask_socketio import SocketIO, emit
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

@dataclass
class DeepPacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    payload_size: int
    ttl: Optional[int]
    flags: str
    application: str
    domain: Optional[str]
    country_src: Optional[str]
    country_dst: Optional[str]
    http_method: Optional[str]
    http_host: Optional[str]
    tls_version: Optional[str]
    sni: Optional[str] = None
    threat_score: int = 0
    raw_payload_hash: Optional[str] = None
    direction: str = "unknown"
    interface: str = "unknown"
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    process_path: Optional[str] = None
    process_user: Optional[str] = None
    app_category: str = "Unknown"
    is_system_process: bool = False
    is_browser: bool = False
    
    def to_dict(self):
        return asdict(self)

@dataclass
class ApplicationProfile:
    name: str
    path: str
    user: str
    category: str
    is_system: bool
    first_seen: float
    last_seen: float
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    total_packets: int = 0
    unique_peers: Set[str] = field(default_factory=set)
    unique_domains: Set[str] = field(default_factory=set)
    unique_countries: Set[str] = field(default_factory=set)
    protocols: Counter = field(default_factory=Counter)
    applications: Counter = field(default_factory=Counter)
    active_connections: int = 0
    threat_score: int = 0
    suspicious_activity: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return {
            'name': self.name,
            'path': self.path,
            'user': self.user,
            'category': self.category,
            'is_system': self.is_system,
            'total_bytes_sent': self.total_bytes_sent,
            'total_bytes_received': self.total_bytes_received,
            'total_bytes': self.total_bytes_sent + self.total_bytes_received,
            'total_packets': self.total_packets,
            'unique_peers': len(self.unique_peers),
            'unique_domains': len(self.unique_domains),
            'unique_countries': len(self.unique_countries),
            'protocols': dict(self.protocols),
            'applications': dict(self.applications),
            'active_connections': self.active_connections,
            'threat_score': self.threat_score,
            'suspicious_activity': self.suspicious_activity[-10:],
            'last_seen': self.last_seen
        }

@dataclass
class ActiveFlow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    application: str
    process_name: str
    process_id: int
    process_path: str
    interface: str
    domain: Optional[str]
    country_src: str
    country_dst: str
    first_seen: float
    last_seen: float
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    status: str = "active"
    http_hosts: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return {
            'flow_id': self.flow_id,
            'src_ip': self.src_ip, 'dst_ip': self.dst_ip,
            'src_port': self.src_port, 'dst_port': self.dst_port,
            'protocol': self.protocol, 'application': self.application,
            'process_name': self.process_name, 'process_id': self.process_id,
            'process_path': self.process_path,
            'interface': self.interface, 'domain': self.domain,
            'country_src': self.country_src, 'country_dst': self.country_dst,
            'first_seen': self.first_seen, 'last_seen': self.last_seen,
            'bytes_sent': self.bytes_sent, 'bytes_received': self.bytes_received,
            'total_bytes': self.bytes_sent + self.bytes_received,
            'total_packets': self.packets_sent + self.packets_received,
            'duration': self.last_seen - self.first_seen,
            'status': self.status
        }

class WindowsProcessInspector:
    """Deep Windows process inspection with socket mapping"""
    
    def __init__(self):
        self.process_cache = {}
        self.socket_to_pid = {}
        self.pid_to_sockets = defaultdict(set)
        self.last_update = 0
        self.lock = threading.Lock()
        
        self.app_categories = {
            'chrome.exe': 'Browser', 'firefox.exe': 'Browser', 'msedge.exe': 'Browser',
            'brave.exe': 'Browser', 'opera.exe': 'Browser', 'vivaldi.exe': 'Browser',
            'svchost.exe': 'System', 'services.exe': 'System', 'lsass.exe': 'System',
            'csrss.exe': 'System', 'smss.exe': 'System', 'wininit.exe': 'System',
            'discord.exe': 'Messaging', 'slack.exe': 'Messaging', 'teams.exe': 'Messaging',
            'zoom.exe': 'Video', 'webex.exe': 'Video',
            'spotify.exe': 'Media', 'vlc.exe': 'Media',
            'steam.exe': 'Gaming', 'epicgameslauncher.exe': 'Gaming',
            'code.exe': 'Development', 'pycharm.exe': 'Development', 'python.exe': 'Development',
            'node.exe': 'Development', 'java.exe': 'Development',
            'docker.exe': 'Infrastructure'
        }
        
        self._start_refresh_loop()
    
    def _start_refresh_loop(self):
        def refresh():
            while True:
                try:
                    self._refresh_data()
                    time.sleep(2)
                except:
                    time.sleep(5)
        
        thread = threading.Thread(target=refresh, daemon=True)
        thread.start()
    
    def _refresh_data(self):
        """Refresh process and socket data"""
        with self.lock:
            new_socket_map = {}
            new_process_cache = {}
            
            # Use netstat for socket-to-PID mapping
            try:
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
                    timeout=5
                )
                
                for line in result.stdout.splitlines():
                    if "TCP" in line or "UDP" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            local_addr = parts[1]
                            pid = parts[-1]
                            if pid.isdigit():
                                pid = int(pid)
                                # Create multiple key formats
                                if ":" in local_addr:
                                    ip, port = local_addr.rsplit(":", 1)
                                    if port.isdigit():
                                        for key in [f"{ip}:{port}", f"0.0.0.0:{port}", 
                                                   f"[::]:{port}", f"127.0.0.1:{port}"]:
                                            new_socket_map[key] = pid
            except:
                pass
            
            # Get process details
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        new_process_cache[pid] = {
                            'pid': pid,
                            'name': proc.info['name'],
                            'exe': proc.info['exe'] or "Unknown",
                            'user': proc.info['username'] or "Unknown",
                            'created': proc.info['create_time']
                        }
                    except:
                        continue
            except:
                pass
            
            self.socket_to_pid = new_socket_map
            self.process_cache = new_process_cache
            self.last_update = time.time()
    
    def get_process_for_connection(self, local_ip, local_port, remote_ip, remote_port):
        """Get process info for a connection"""
        if not IS_WINDOWS:
            return None
            
        with self.lock:
            keys = [
                f"{local_ip}:{local_port}",
                f"0.0.0.0:{local_port}",
                f"[::]:{local_port}",
                f"127.0.0.1:{local_port}"
            ]
            
            pid = None
            for key in keys:
                if key in self.socket_to_pid:
                    pid = self.socket_to_pid[key]
                    break
            
            if not pid or pid not in self.process_cache:
                return None
            
            info = self.process_cache[pid]
            proc_name = info.get('name', 'Unknown').lower()
            
            # Determine category
            category = "Unknown"
            for known, cat in self.app_categories.items():
                if known in proc_name:
                    category = cat
                    break
            
            is_system = 'system' in info.get('user', '').lower()
            
            return {
                'pid': pid,
                'name': info.get('name', 'Unknown'),
                'path': info.get('exe', 'Unknown'),
                'user': info.get('user', 'Unknown'),
                'created': info.get('created', 0),
                'category': category,
                'is_system': is_system,
                'is_browser': category == 'Browser'
            }

class MultiInterfaceAggregator:
    """Aggregate traffic from all network interfaces"""
    
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.interface_threads = {}
        self.interface_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'errors': 0})
        self.running = False
    
    def get_all_interfaces(self):
        """Get all available network interfaces"""
        interfaces = []
        try:
            if IS_WINDOWS:
                for iface in get_windows_if_list():
                    name = iface.get('name', '')
                    desc = iface.get('description', 'Unknown')
                    if name:
                        interfaces.append((name, desc))
            else:
                for iface in get_if_list():
                    interfaces.append((iface, iface))
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        return interfaces
    
    def start_multi_capture(self, filter_expr="ip"):
        """Start capture on all interfaces"""
        self.running = True
        interfaces = self.get_all_interfaces()
        
        print(f"[+] Found {len(interfaces)} interface(s):")
        for i, (name, desc) in enumerate(interfaces[:5]):
            print(f"    [{i}] {desc[:50]}")
        
        for name, desc in interfaces:
            thread = threading.Thread(
                target=self._capture_interface,
                args=(name, desc, filter_expr),
                daemon=True
            )
            thread.start()
            self.interface_threads[name] = thread
        
        return len(interfaces) > 0
    
    def _capture_interface(self, interface_name, description, filter_expr):
        """Capture on specific interface"""
        def packet_handler(pkt):
            if not self.running:
                return
            try:
                processed = self.analyzer._process_packet(pkt, interface_name)
                if processed:
                    self.analyzer.packet_queue.put(processed)
                    self.interface_stats[interface_name]['packets'] += 1
                    self.interface_stats[interface_name]['bytes'] += processed.length
            except Exception as e:
                self.interface_stats[interface_name]['errors'] += 1
        
        try:
            sniff(
                iface=interface_name,
                filter=filter_expr,
                prn=packet_handler,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"[-] Interface {description[:30]} error: {e}")
    
    def stop(self):
        self.running = False
        for thread in self.interface_threads.values():
            thread.join(timeout=2)

class DeepTrafficAnalyzer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.packets_history = deque(maxlen=10000)
        self.active_flows = {}
        self.application_profiles = {}
        self.flow_lock = threading.Lock()
        self.profile_lock = threading.Lock()
        
        self.process_inspector = WindowsProcessInspector() if IS_WINDOWS else None
        self.multi_interface = MultiInterfaceAggregator(self)
        
        self.domain_stats = defaultdict(lambda: {
            'bytes_in': 0, 'bytes_out': 0, 'connections': set(),
            'ips': set(), 'first_seen': None, 'last_seen': None, 'apps': set()
        })
        
        self.geo_cache = {}
        self.dns_cache = {}
        self.blocklist = set()
        self.stats = {
            'total_packets': 0, 'total_bytes': 0,
            'unique_ips': set(), 'unique_domains': set(),
            'protocols': Counter(), 'countries': Counter(),
            'applications': Counter(), 'app_categories': Counter(),
            'threats': [], 'interfaces': Counter()
        }
        
        self.running = False
        self.capture_thread = None
        
        self.local_networks = [
            '192.168.', '10.', '172.16.', '172.17.', '172.18.', 
            '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
            '172.29.', '172.30.', '172.31.', '127.', '169.254.',
            '::1', 'fe80::', 'fc00:', 'fd00:'
        ]
        
        self._start_background_updater()
    
    def _start_background_updater(self):
        def updater():
            while True:
                try:
                    self._update_application_profiles()
                    time.sleep(5)
                except:
                    time.sleep(10)
        
        thread = threading.Thread(target=updater, daemon=True)
        thread.start()
    
    def _is_private_ip(self, ip):
        return any(ip.startswith(prefix) for prefix in self.local_networks)
    
    def _get_geolocation(self, ip):
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        if self._is_private_ip(ip):
            self.geo_cache[ip] = 'Private/Local'
            return 'Private/Local'
        try:
            import urllib.request
            req = urllib.request.Request(
                f'http://ip-api.com/json/{ip}?fields=country',
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                country = data.get('country', 'Unknown')
                self.geo_cache[ip] = country
                return country
        except:
            self.geo_cache[ip] = 'Unknown'
            return 'Unknown'
    
    def _get_domain(self, ip):
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        try:
            domain = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = domain
            return domain
        except:
            self.dns_cache[ip] = None
            return None
    
    def _deep_packet_inspection(self, packet):
        """Deep packet inspection"""
        app_data = {}
        
        if not SCAPY_AVAILABLE:
            return ("Unknown", app_data)
        
        def extract_sni(payload):
            if len(payload) < 43:
                return None
            try:
                if payload[0] == 0x16:
                    session_id_len = payload[43]
                    pos = 44 + session_id_len
                    if len(payload) > pos + 2:
                        cipher_suites_len = struct.unpack('!H', payload[pos:pos+2])[0]
                        pos += 2 + cipher_suites_len
                        if len(payload) > pos + 1:
                            compression_len = payload[pos]
                            pos += 1 + compression_len
                            if len(payload) > pos + 2:
                                extensions_len = struct.unpack('!H', payload[pos:pos+2])[0]
                                pos += 2
                                end = pos + extensions_len
                                while pos < end and pos < len(payload) - 4:
                                    ext_type = struct.unpack('!H', payload[pos:pos+2])[0]
                                    ext_len = struct.unpack('!H', payload[pos+2:pos+4])[0]
                                    if ext_type == 0x0000:
                                        sni_list_len = struct.unpack('!H', payload[pos+6:pos+8])[0]
                                        sni_type = payload[pos+8]
                                        sni_len = struct.unpack('!H', payload[pos+9:pos+11])[0]
                                        return payload[pos+11:pos+11+sni_len].decode('utf-8', errors='ignore')
                                    pos += 4 + ext_len
            except:
                pass
            return None
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            payload = bytes(tcp.payload) if tcp.payload else b''
            
            if payload:
                try:
                    payload_str = payload[:1000].decode('utf-8', errors='ignore')
                    
                    if any(method in payload_str for method in ['GET ', 'POST ', 'HTTP/']):
                        app_data['protocol'] = 'HTTP'
                        lines = payload_str.split('\r\n')
                        for line in lines:
                            if line.lower().startswith('host:'):
                                app_data['host'] = line.split(':', 1)[1].strip()
                        return ("HTTP", app_data)
                    
                    if tcp.dport == 443 or tcp.sport == 443:
                        sni = extract_sni(payload)
                        if sni:
                            app_data['sni'] = sni
                            app_data['host'] = sni
                        return ("HTTPS", app_data)
                    
                    if payload.startswith(b'SSH-'):
                        return ("SSH", app_data)
                        
                except:
                    pass
            
            port_map = {
                22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
                110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 
                993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
                5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy"
            }
            if tcp.dport in port_map:
                return (port_map[tcp.dport], app_data)
            if tcp.sport in port_map:
                return (port_map[tcp.sport], app_data)
                
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.dport == 53 or udp.sport == 53:
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    if dns.qd:
                        try:
                            qname = dns.qd.qname
                            if isinstance(qname, bytes):
                                domain = qname.decode().rstrip('.')
                            else:
                                domain = str(qname).rstrip('.')
                            app_data['host'] = domain
                        except:
                            pass
                return ("DNS", app_data)
            if udp.dport == 123 or udp.sport == 123:
                return ("NTP", app_data)
        
        return ("Unknown", app_data)
    
    def _calculate_threat_score(self, packet_info):
        score = 0
        reasons = []
        
        if packet_info.dst_ip in self.blocklist or packet_info.src_ip in self.blocklist:
            score += 50
            reasons.append("IP in blocklist")
        
        if packet_info.domain and any(d in str(packet_info.domain) for d in self.blocklist):
            score += 40
            reasons.append("Domain in blocklist")
        
        suspicious_ports = [4444, 5555, 6666, 31337, 12345, 54321]
        if packet_info.dst_port in suspicious_ports:
            score += 30
            reasons.append(f"Suspicious port {packet_info.dst_port}")
        
        packet_info.threat_reasons = reasons
        return min(score, 100)
    
    def _get_flow_id(self, src_ip, dst_ip, src_port, dst_port, protocol):
        endpoints = sorted([(src_ip, src_port or 0), (dst_ip, dst_port or 0)])
        return f"{endpoints[0][0]}:{endpoints[0][1]}<->{endpoints[1][0]}:{endpoints[1][1]}|{protocol}"
    
    def _determine_direction(self, src_ip, dst_ip):
        src_private = self._is_private_ip(src_ip)
        dst_private = self._is_private_ip(dst_ip)
        if src_private and dst_private:
            return "internal"
        elif src_private and not dst_private:
            return "outbound"
        elif not src_private and dst_private:
            return "inbound"
        else:
            return "external"
    
    def _process_packet(self, packet, interface="unknown"):
        """Process a single packet"""
        if not SCAPY_AVAILABLE:
            return None
            
        try:
            timestamp = time.time()
            src_ip, dst_ip = None, None
            src_port, dst_port = None, None
            protocol = "OTHER"
            length = len(packet)
            payload_size = 0
            ttl = None
            flags = ""
            
            if packet.haslayer(IP):
                ip = packet[IP]
                src_ip, dst_ip = ip.src, ip.dst
                ttl = ip.ttl
                protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip.proto, "OTHER")
            elif packet.haslayer(ARP):
                src_ip, dst_ip = packet[ARP].psrc, packet[ARP].pdst
                protocol = "ARP"
            
            if not src_ip or not dst_ip:
                return None
            
            app, app_data = self._deep_packet_inspection(packet)
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                flags = str(tcp.flags) if hasattr(tcp, 'flags') else ""
                payload = bytes(tcp.payload) if tcp.payload else b''
                payload_size = len(payload)
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                src_port, dst_port = udp.sport, udp.dport
                payload = bytes(udp.payload) if udp.payload else b''
                payload_size = len(payload)
            
            country_src = self._get_geolocation(src_ip)
            country_dst = self._get_geolocation(dst_ip)
            domain = app_data.get('host') or app_data.get('sni') or self._get_domain(dst_ip)
            direction = self._determine_direction(src_ip, dst_ip)
            
            # Get process info
            local_ip, local_port = (src_ip, src_port) if self._is_private_ip(src_ip) else (dst_ip, dst_port)
            process_info = None
            if self.process_inspector:
                process_info = self.process_inspector.get_process_for_connection(
                    local_ip, local_port or 0, dst_ip, dst_port or 0
                )
            
            packet_info = DeepPacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                payload_size=payload_size,
                ttl=ttl,
                flags=flags,
                application=app,
                domain=domain,
                country_src=country_src,
                country_dst=country_dst,
                http_method=app_data.get('method'),
                http_host=app_data.get('host'),
                tls_version=app_data.get('tls_version'),
                sni=app_data.get('sni'),
                threat_score=0,
                raw_payload_hash=hashlib.sha256(str(timestamp).encode()).hexdigest()[:16],
                direction=direction,
                interface=interface,
                process_name=process_info.get('name') if process_info else None,
                process_id=process_info.get('pid') if process_info else None,
                process_path=process_info.get('path') if process_info else None,
                process_user=process_info.get('user') if process_info else None,
                app_category=process_info.get('category', 'Unknown') if process_info else 'Unknown',
                is_system_process=process_info.get('is_system', False) if process_info else False,
                is_browser=process_info.get('is_browser', False) if process_info else False
            )
            
            packet_info.threat_score = self._calculate_threat_score(packet_info)
            
            self._update_flow(packet_info)
            self._update_domain_stats(packet_info)
            
            self.stats['total_packets'] += 1
            self.stats['total_bytes'] += length
            self.stats['unique_ips'].add(src_ip)
            self.stats['unique_ips'].add(dst_ip)
            if domain:
                self.stats['unique_domains'].add(domain)
            self.stats['protocols'][protocol] += 1
            self.stats['applications'][app] += 1
            self.stats['interfaces'][interface] += 1
            
            if packet_info.app_category:
                self.stats['app_categories'][packet_info.app_category] += 1
            
            if direction == "outbound":
                self.stats['countries'][country_dst] += 1
            elif direction == "inbound":
                self.stats['countries'][country_src] += 1
            
            if packet_info.threat_score > 50:
                self.stats['threats'].append({
                    'time': datetime.fromtimestamp(timestamp).isoformat(),
                    'src': src_ip, 'dst': dst_ip,
                    'sport': src_port, 'dport': dst_port,
                    'domain': domain, 'application': app,
                    'score': packet_info.threat_score,
                    'process': packet_info.process_name,
                    'reasons': getattr(packet_info, 'threat_reasons', [])
                })
            
            self.packets_history.append(packet_info.to_dict())
            
            return packet_info
            
        except Exception as e:
            print(f"Packet error: {e}")
            return None
    
    def _update_flow(self, packet_info):
        """Update flow tracking"""
        with self.flow_lock:
            flow_id = self._get_flow_id(
                packet_info.src_ip, packet_info.dst_ip,
                packet_info.src_port or 0, packet_info.dst_port or 0,
                packet_info.protocol
            )
            
            direction = packet_info.direction
            
            if flow_id not in self.active_flows:
                if self._is_private_ip(packet_info.src_ip):
                    local_ip, local_port = packet_info.src_ip, packet_info.src_port or 0
                    remote_ip, remote_port = packet_info.dst_ip, packet_info.dst_port or 0
                else:
                    local_ip, local_port = packet_info.dst_ip, packet_info.dst_port or 0
                    remote_ip, remote_port = packet_info.src_ip, packet_info.src_port or 0
                
                self.active_flows[flow_id] = ActiveFlow(
                    flow_id=flow_id,
                    src_ip=local_ip,
                    dst_ip=remote_ip,
                    src_port=local_port,
                    dst_port=remote_port,
                    protocol=packet_info.protocol,
                    application=packet_info.application,
                    process_name=packet_info.process_name or "Unknown",
                    process_id=packet_info.process_id or 0,
                    process_path=packet_info.process_path or "Unknown",
                    interface=packet_info.interface,
                    domain=packet_info.domain,
                    country_src=self._get_geolocation(local_ip),
                    country_dst=self._get_geolocation(remote_ip),
                    first_seen=packet_info.timestamp,
                    last_seen=packet_info.timestamp
                )
            
            flow = self.active_flows[flow_id]
            flow.last_seen = packet_info.timestamp
            
            if direction == "outbound":
                flow.bytes_sent += packet_info.length
                flow.packets_sent += 1
            elif direction == "inbound":
                flow.bytes_received += packet_info.length
                flow.packets_received += 1
            else:
                flow.bytes_sent += packet_info.length // 2
                flow.bytes_received += packet_info.length // 2
                flow.packets_sent += 1
                flow.packets_received += 1
            
            if packet_info.domain and not flow.domain:
                flow.domain = packet_info.domain
            
            if packet_info.http_host and packet_info.http_host not in flow.http_hosts:
                flow.http_hosts.append(packet_info.http_host)
    
    def _update_domain_stats(self, packet_info):
        """Update domain statistics"""
        domain = packet_info.domain
        if not domain:
            return
        
        stats = self.domain_stats[domain]
        direction = packet_info.direction
        
        if direction == "outbound":
            stats['bytes_out'] += packet_info.length
        elif direction == "inbound":
            stats['bytes_in'] += packet_info.length
        else:
            stats['bytes_out'] += packet_info.length // 2
            stats['bytes_in'] += packet_info.length // 2
        
        stats['connections'].add(f"{packet_info.src_ip}->{packet_info.dst_ip}")
        stats['ips'].add(packet_info.dst_ip if not self._is_private_ip(packet_info.dst_ip) else packet_info.src_ip)
        stats['apps'].add(packet_info.process_name or "Unknown")
        
        if not stats['first_seen']:
            stats['first_seen'] = packet_info.timestamp
        stats['last_seen'] = packet_info.timestamp
    
    def _update_application_profiles(self):
        """Update aggregated application profiles"""
        with self.profile_lock, self.flow_lock:
            self.application_profiles = {}
            
            for flow in self.active_flows.values():
                app_key = f"{flow.process_name}:{flow.process_path}"
                
                if app_key not in self.application_profiles:
                    self.application_profiles[app_key] = ApplicationProfile(
                        name=flow.process_name,
                        path=flow.process_path,
                        user="Unknown",
                        category="Unknown",
                        is_system=False,
                        first_seen=flow.first_seen,
                        last_seen=flow.last_seen
                    )
                
                profile = self.application_profiles[app_key]
                profile.last_seen = flow.last_seen
                profile.total_bytes_sent += flow.bytes_sent
                profile.total_bytes_received += flow.bytes_received
                profile.total_packets += flow.packets_sent + flow.packets_received
                profile.unique_peers.add(flow.dst_ip)
                if flow.domain:
                    profile.unique_domains.add(flow.domain)
                profile.unique_countries.add(flow.country_dst)
                profile.protocols[flow.protocol] += 1
                profile.applications[flow.application] += 1
    
    def start_capture(self, interface=None, filter_expr="ip", offline_file=None):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            print("ERROR: Scapy not available")
            return False
        
        self.running = True
        
        if offline_file:
            def capture():
                try:
                    packets = rdpcap(offline_file)
                    for i, packet in enumerate(packets):
                        if not self.running:
                            break
                        self._process_packet(packet, "offline")
                        if i % 100 == 0:
                            time.sleep(0.001)
                    print(f"[+] Finished reading {len(packets)} packets")
                except Exception as e:
                    print(f"Offline error: {e}")
                    self.running = False
            
            self.capture_thread = threading.Thread(target=capture, daemon=True)
            self.capture_thread.start()
            return True
        
        if interface == "all":
            return self.multi_interface.start_multi_capture(filter_expr)
        else:
            def capture():
                try:
                    sniff(iface=interface, filter=filter_expr,
                          prn=lambda p: self._process_packet(p, interface) if self._process_packet(p, interface) else None,
                          store=0, stop_filter=lambda x: not self.running)
                except Exception as e:
                    print(f"Capture error: {e}")
                    self.running = False
            
            self.capture_thread = threading.Thread(target=capture, daemon=True)
            self.capture_thread.start()
            print(f"[+] Capture started on {interface or 'default'}")
            return True
    
    def stop_capture(self):
        self.running = False
        self.multi_interface.stop()
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def get_packets(self, count=100):
        return list(self.packets_history)[-count:]
    
    def get_active_flows(self, limit=100, app_filter=None):
        with self.flow_lock:
            flows = list(self.active_flows.values())
            if app_filter:
                flows = [f for f in flows if app_filter.lower() in f.process_name.lower()]
            flows = sorted(flows, key=lambda x: x.bytes_sent + x.bytes_received, reverse=True)[:limit]
            return [f.to_dict() for f in flows]
    
    def get_application_profiles(self, limit=50):
        with self.profile_lock:
            profiles = sorted(
                self.application_profiles.values(),
                key=lambda x: x.total_bytes_sent + x.total_bytes_received,
                reverse=True
            )[:limit]
            return [p.to_dict() for p in profiles]
    
    def get_domain_stats(self, limit=30):
        sorted_domains = sorted(
            self.domain_stats.items(),
            key=lambda x: x[1]['bytes_in'] + x[1]['bytes_out'],
            reverse=True
        )[:limit]
        
        result = []
        for domain, stats in sorted_domains:
            result.append({
                'domain': domain,
                'bytes_in': stats['bytes_in'],
                'bytes_out': stats['bytes_out'],
                'total_bytes': stats['bytes_in'] + stats['bytes_out'],
                'connections': len(stats['connections']),
                'ips': len(stats['ips']),
                'apps': list(stats['apps'])[:5]
            })
        return result
    
    def get_interface_stats(self):
        return dict(self.multi_interface.interface_stats) if self.multi_interface else {}
    
    def get_statistics(self):
        current_time = time.time()
        
        with self.flow_lock:
            active_count = 0
            for flow in self.active_flows.values():
                if current_time - flow.last_seen > 300:
                    flow.status = "idle"
                else:
                    active_count += 1
        
        return {
            'total_packets': self.stats['total_packets'],
            'total_bytes': self.stats['total_bytes'],
            'unique_ips': len(self.stats['unique_ips']),
            'unique_domains': len(self.stats['unique_domains']),
            'active_flows': active_count,
            'total_flows': len(self.active_flows),
            'protocols': dict(self.stats['protocols']),
            'applications': dict(self.stats['applications']),
            'app_categories': dict(self.stats['app_categories']),
            'top_countries': dict(self.stats['countries'].most_common(10)),
            'interfaces': dict(self.stats['interfaces']),
            'interface_stats': self.get_interface_stats(),
            'active_threats': len([t for t in self.stats['threats'] 
                                  if current_time - datetime.fromisoformat(t['time']).timestamp() < 300]),
            'threats': self.stats['threats'][-20:],
            'timestamp': current_time
        }

class ExportManager:
    def __init__(self, output_dir="exports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def export_to_json(self, data, filename=None):
        if filename is None:
            filename = f"forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return str(filepath)
    
    def export_to_csv(self, flows, filename=None):
        if filename is None:
            filename = f"flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = self.output_dir / filename
        
        if not flows:
            return None
        
        fieldnames = ['flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                     'protocol', 'application', 'process_name', 'process_id',
                     'bytes_sent', 'bytes_received', 'domain', 'interface']
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for flow in flows:
                row = {k: flow.get(k, '') for k in fieldnames}
                writer.writerow(row)
        return str(filepath)

# Dashboard HTML (abbreviated for length - use previous full version)
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Deep Network Forensics</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #0a0a0f; color: #e0e0e0; margin: 0; }
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 20px; border-bottom: 2px solid #00d4ff; }
        .container { max-width: 1920px; margin: 0 auto; padding: 20px; display: grid; grid-template-columns: 300px 1fr 350px; gap: 20px; }
        .card { background: #1a1a2e; border-radius: 16px; padding: 20px; border: 1px solid rgba(0,212,255,0.2); }
        .app-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; }
        .app-card { background: rgba(0,0,0,0.2); border-radius: 12px; padding: 15px; border-left: 4px solid #00d4ff; }
        .metric-value { color: #00d4ff; font-weight: 700; font-family: monospace; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
        th { text-align: left; padding: 12px; color: #00d4ff; border-bottom: 2px solid rgba(0,212,255,0.2); }
        td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        tr:hover { background: rgba(0,212,255,0.05); }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Deep Network Forensics <span style="background:#00a4ef; color:white; padding:5px 15px; border-radius:20px; font-size:0.5em;">Windows</span></h1>
        <div id="status-bar">Initializing...</div>
    </div>
    <div class="container">
        <div class="sidebar">
            <div class="card">
                <h3>Interfaces</h3>
                <div id="interface-stats">Loading...</div>
            </div>
        </div>
        <div class="main">
            <div class="card">
                <h3>Applications</h3>
                <div id="app-grid" class="app-grid">Waiting for traffic...</div>
            </div>
            <div class="card">
                <h3>Active Flows</h3>
                <table id="flows-table">
                    <thead><tr><th>Process</th><th>Local</th><th>Remote</th><th>Domain</th><th>Sent</th><th>Received</th></tr></thead>
                    <tbody id="flows-body"><tr><td colspan="6" style="text-align:center; padding:40px;">No flows</td></tr></tbody>
                </table>
            </div>
        </div>
        <div class="sidebar">
            <div class="card">
                <h3>Protocols</h3>
                <canvas id="protocolChart"></canvas>
            </div>
        </div>
    </div>
    <script>
        const socket = io();
        let protocolChart;
        
        function initCharts() {
            const ctx = document.getElementById('protocolChart').getContext('2d');
            protocolChart = new Chart(ctx, {
                type: 'doughnut',
                data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00d4ff', '#00ff88', '#ff00ff', '#ffaa00', '#ff4444'] }] },
                options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#e0e0e0' } } } }
            });
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        socket.on('connect', () => console.log('Connected'));
        
        socket.on('stats_update', (data) => {
            document.getElementById('status-bar').innerHTML = 
                `Packets: ${data.total_packets.toLocaleString()} | ` +
                `Flows: ${data.active_flows} | ` +
                `Threats: ${data.active_threats}`;
            
            if (data.protocols && Object.keys(data.protocols).length > 0) {
                protocolChart.data.labels = Object.keys(data.protocols);
                protocolChart.data.datasets[0].data = Object.values(data.protocols);
                protocolChart.update();
            }
        });
        
        socket.on('apps_update', (apps) => {
            const grid = document.getElementById('app-grid');
            if (apps.length === 0) {
                grid.innerHTML = 'Waiting for traffic...';
                return;
            }
            grid.innerHTML = apps.map(app => `
                <div class="app-card">
                    <div style="font-weight:600">${app.name}</div>
                    <div style="font-size:0.8em; color:#888">${app.category}</div>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:10px; font-size:0.85em;">
                        <div>↓ ${formatBytes(app.total_bytes_received)}</div>
                        <div>↑ ${formatBytes(app.total_bytes_sent)}</div>
                    </div>
                </div>
            `).join('');
        });
        
        socket.on('flows_update', (flows) => {
            const tbody = document.getElementById('flows-body');
            if (flows.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:40px;">No active flows</td></tr>';
                return;
            }
            tbody.innerHTML = flows.map(flow => `
                <tr>
                    <td>${flow.process_name}<br><small>PID: ${flow.process_id}</small></td>
                    <td>${flow.src_ip}:${flow.src_port}</td>
                    <td>${flow.dst_ip}:${flow.dst_port}</td>
                    <td>${flow.domain || '-'}</td>
                    <td style="color:#ff6b6b">${formatBytes(flow.bytes_sent)}</td>
                    <td style="color:#51cf66">${formatBytes(flow.bytes_received)}</td>
                </tr>
            `).join('');
        });
        
        initCharts();
    </script>
</body>
</html>"""

class ForensicsDashboard:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='threading')
        self.setup_routes()
        
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return render_template_string(DASHBOARD_HTML)
        
        @self.app.route('/api/stats')
        def api_stats():
            return jsonify(self.analyzer.get_statistics())
        
        @self.app.route('/api/apps')
        def api_apps():
            return jsonify(self.analyzer.get_application_profiles(50))
        
        @self.app.route('/api/flows')
        def api_flows():
            return jsonify(self.analyzer.get_active_flows(100))
        
        @self.socketio.on('connect')
        def handle_connect():
            emit('stats_update', self.analyzer.get_statistics())
            emit('apps_update', self.analyzer.get_application_profiles())
            emit('flows_update', self.analyzer.get_active_flows())
    
    def broadcast_loop(self):
        while self.analyzer.running:
            try:
                stats = self.analyzer.get_statistics()
                self.socketio.emit('stats_update', stats)
                
                if int(time.time()) % 2 == 0:
                    apps = self.analyzer.get_application_profiles()
                    self.socketio.emit('apps_update', apps)
                
                if int(time.time()) % 2 == 1:
                    flows = self.analyzer.get_active_flows()
                    self.socketio.emit('flows_update', flows)
                
                time.sleep(1)
            except Exception as e:
                print(f"Broadcast error: {e}")
                time.sleep(2)
    
    def run(self, host='0.0.0.0', port=5000):
        if not FLASK_AVAILABLE:
            print("ERROR: Flask not available")
            return
        
        thread = threading.Thread(target=self.broadcast_loop, daemon=True)
        thread.start()
        print(f"[+] Dashboard: http://{host}:{port}")
        
        try:
            self.socketio.run(self.app, host=host, port=port, allow_unsafe_werkzeug=True)
        except Exception as e:
            print(f"Dashboard error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Deep Network Forensics')
    parser.add_argument('-i', '--interface', default='all', help='Interface (default: all)')
    parser.add_argument('-f', '--file', help='Offline pcap file')
    parser.add_argument('--filter', default='ip', help='BPF filter')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Dashboard port')
    parser.add_argument('--no-dashboard', action='store_true', help='CLI mode')
    parser.add_argument('--list-interfaces', action='store_true', help='List interfaces')
    parser.add_argument('--admin', action='store_true', help='Auto-elevate admin')
    
    args = parser.parse_args()
    
    if args.admin and not is_admin():
        run_as_admin()
    
    print(f"""
╔════════════════════════════════════════════════════════════════╗
║     DEEP NETWORK FORENSICS v{__version__}                    ║
║          Windows Application-Aware Analysis                    ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Check Npcap
    npcap_ok, npcap_path = check_npcap()
    if not npcap_ok:
        print("[!] WARNING: Npcap not detected!")
        print("    Install from: https://npcap.com/#download\n")
    else:
        print(f"[+] Npcap detected: {npcap_path}")
    
    if not is_admin():
        print("[!] WARNING: Not running as Administrator\n")
    
    if args.list_interfaces:
        print("\nAvailable Interfaces:")
        print("-" * 60)
        try:
            if IS_WINDOWS:
                for i, iface in enumerate(get_windows_if_list()):
                    print(f"[{i}] {iface.get('description', 'Unknown')}")
                    print(f"    Name: {iface.get('name', 'N/A')}")
                    print()
            else:
                for i, iface in enumerate(get_if_list()):
                    print(f"[{i}] {iface}")
        except Exception as e:
            print(f"Error: {e}")
        return
    
    if not SCAPY_AVAILABLE:
        print("ERROR: Scapy not installed")
        print("Run: pip install scapy psutil")
        return
    
    analyzer = DeepTrafficAnalyzer()
    
    print(f"\n[+] Starting capture on: {args.interface}")
    if args.interface == 'all':
        print("    Capturing from ALL interfaces...")
    
    if not analyzer.start_capture(
        interface=args.interface if args.interface != 'all' else 'all',
        filter_expr=args.filter,
        offline_file=args.file
    ):
        print("[-] Failed to start capture")
        return
    
    print("[+] Capture started")
    
    if args.no_dashboard:
        print("[+] CLI mode (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(5)
                stats = analyzer.get_statistics()
                apps = analyzer.get_application_profiles(5)
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Packets: {stats['total_packets']:,} | "
                      f"Apps: {len(apps)} | "
                      f"Threats: {stats['active_threats']}")
        except KeyboardInterrupt:
            print("\n[!] Stopping...")
    else:
        print("[+] Starting dashboard...")
        dashboard = ForensicsDashboard(analyzer)
        try:
            dashboard.run(port=args.port)
        except KeyboardInterrupt:
            print("\n[!] Shutting down...")
    
    analyzer.stop_capture()
    print("[+] Goodbye!")

if __name__ == "__main__":
    main()