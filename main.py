from scapy.all import sniff, IP
from datetime import datetime
import socket
import netifaces
import psutil
import matplotlib.pyplot as plt

MAX_FILE_SIZE_MB = 3
current_log_file = None
current_log_start_time = None
throughput_data = {'timestamps': [], 'throughputs': []}


def create_new_log_file():
    global current_log_file, current_log_start_time
    current_log_start_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    current_log_file = open(f"{current_log_start_time}.txt", "w")


def close_current_log_file():
    global current_log_file
    if current_log_file:
        current_log_file.close()


def update_throughput_data(timestamp, packet_size):
    throughput_data['timestamps'].append(timestamp)
    throughput_data['throughputs'].append(packet_size)


def plot_throughput():
    plt.plot(throughput_data['timestamps'], throughput_data['throughputs'])
    plt.xlabel('Timestamp')
    plt.ylabel('Throughput (bytes)')
    plt.title('Network Throughput Over Time')
    plt.show()


def get_protocol_name(proto):
    protocol_names = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        50: 'ESP',
        51: 'AH',
        89: 'OSPF',
        132: 'SCTP',
        143: 'IPv6-ICMP',
        254: 'IGMP',

    }
    return protocol_names.get(proto, f'Unknown({proto})')


def get_process_info(src_ip, src_port):
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.laddr.ip == src_ip and conn.laddr.port == src_port:
                process = psutil.Process(conn.pid)
                return process.name(), conn.pid
        return "Unknown", None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown", None


def get_direction(src_ip, dst_ip):
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipv4_address = addresses[netifaces.AF_INET][0]['addr']
            if src_ip == ipv4_address:
                return "Outgoing"
            elif dst_ip == ipv4_address:
                return "Incoming"
    return "Unknown"


def calculate_throughput(timestamp, packet_size):
    update_throughput_data(timestamp, packet_size)


def packet_callback(packet):
    global current_log_file, current_log_start_time
    if IP in packet and hasattr(packet[IP], 'sport') and hasattr(packet[IP], 'dport'):
        # Получение информации о пакете
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[IP].sport
        dst_port = packet[IP].dport
        protocol = packet[IP].proto
        packet_size = len(packet)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        traffic_direction = get_direction(src_ip, dst_ip)

        process_name, pid = get_process_info(src_ip, src_port)

        protocol_name = get_protocol_name(protocol)

        arrow = '<-' if traffic_direction == 'Incoming' else '->'
        pid_info = f", PID: {pid}" if pid is not None else ""
        log_entry = f"{timestamp} - {src_ip}:{src_port} {arrow} {dst_ip}:{dst_port} (Protocol: {protocol_name}, Process: {process_name}{pid_info}, Packet Size: {packet_size} bytes)\n"

        if current_log_file is None or current_log_file.tell() >= MAX_FILE_SIZE_MB * 1024 * 1024:
            close_current_log_file()
            create_new_log_file()

        current_log_file.write(log_entry)
        current_log_file.flush()

        calculate_throughput(timestamp, packet_size)


create_new_log_file()

sniff(prn=packet_callback, store=0)

plot_throughput()

close_current_log_file()
