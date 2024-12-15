import socket
import utils
from scapy.all import IP, TCP, sr, send, conf # type: ignore

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
		results = []
		responses, _ = sr(IP(dst=host) / TCP(dport=ports, flags='S'), timeout=0.5)
		for respone in responses:
			if respone[1].haslayer(TCP) and respone[1][TCP].flags == "SA":
				service = utils.get_service(respone[0][TCP].dport, "tcp")
				results.append((respone[0][TCP].dport, "open", service))
				open_ports += 1
			elif len(ports) <= 11:
				service = utils.get_service(respone[0][TCP].dport, "tcp")
				results.append((respone[0][TCP].dport, "close", service))

		results.sort(key=lambda x: x[0])
		for port, status, service in results:
			print(f"{port}/tcp\t{status}\t{service}")

		return open_ports
	except PermissionError:
		print("\nOperation not permitted. Please run as root or with appropriate permissions.")
		exit(1)