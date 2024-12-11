from datetime import datetime

def print_info(host: str) -> None:
	print(f"Starting scanning at {datetime.now().strftime("%Y-%m-%d %H:%M")}")
	print(f"Nmap scan report for {host}")

def get_service(port: int, protocol: str) -> str:
	if protocol == "tcp":
		file = open("./lists/tcp_services")
	elif protocol == "udp":
		file = open("./lists/udp_services")
	else:
		return -1
	for line in file:
		if str(port) == line.split("\t")[1].split("/")[0]:
			file.close()
			return line.split("\t")[0]
	file.close()
	return "unknown"

def print_connections(args, tcp_ports, udp_ports) -> None:
	if tcp_ports != 0 or udp_ports != 0:
		print("PORT\tSTATE\tSERVICE")
	if args["sT"]:
		print(f"Not shown: {len(args['p']) - tcp_ports} close tcp ports (no-response)")
	if args["sU"]:
		print(f"Not shown: {len(args['p']) - udp_ports} close udp ports (no-response)")