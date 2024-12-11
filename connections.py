import socket
import utils
from scapy.all import IP, TCP, sr1, send, conf # type: ignore

def check_tcp_connection(host: str, ports: list[int]) -> tuple[int, list[str]]:
	open_ports = 0
	ports_count = len(ports)
	for port in ports:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(0.5)
		result = sock.connect_ex((host, port))
		if result == 0:
			service = utils.get_service(port, "tcp")
			print(f"{port}/tcp\topen\t{service}")
			open_ports += 1
		elif ports_count <= 11:
				service = utils.get_service(port, "tcp")
				print(f"{port}/tcp\tclose\t{service}")
		sock.close()
	return open_ports

def check_udp_connection(host: str, ports: list[int]) -> tuple[int, list[str]]:
	open_ports = 0
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		for port in ports:
			sock.settimeout(0.5)
			sock.sendto(b"", (host, port))
			try:
				sock.recvfrom(1024)
				service = utils.get_service(port, "udp")
				print(f"{port}/udp\topen\t{service}")
				open_ports += 1
			except Exception:
				if len(ports) <= 11:
					service = utils.get_service(port, "udp")
					print(f"{port}/udp\tclose\t{service}")
	return open_ports

def check_syn_connection(host: str, ports: list[int]) -> tuple[int, list[str]]:
	try:
		conf.verb = 0
		open_ports = 0
		ip_layer = IP(dst=host)
		for port in ports:
			tcp_syn = TCP(dport=port, flags='S')
			syn_packet = ip_layer / tcp_syn

			response = sr1(syn_packet, timeout=0.5)
			if response and response[TCP].flags == "SA" and response.haslayer(TCP):
				open_ports += 1
				service = utils.get_service(port, "tcp")
				print(f"{port}/tcp\topen\t{service}")
				tcp_rst = TCP(dport=port, sport=response[TCP].sport, flags="R")
				rst_packet = ip_layer / tcp_rst
				send(rst_packet)
			elif len(ports) <= 11:
				service = utils.get_service(port, "tcp")
				print(f"{port}/tcp\tclose\t{service}")
		return open_ports
	except PermissionError:
		print("\nOperation not permitted. Please run as root or with appropriate permissions.")
		exit(1)