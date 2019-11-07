import pandas as pd
import ipaddress

class Firewall:


	def __init__(self, csv_file_name):
		# Read CSV file into a pandas dataframe with columns for each field
		self.df = pd.read_csv(csv_file_name, names=["direction", "protocol", "port", "ip_address"])

	'''
	This function is used when the ip_address entry in the dataframe is a range
	Detects whether ip address passed into accept_packet is in given range
	'''
	def ip_in_range(self, ip_range, IP):
		min_ip, max_ip = ip_range.split('-')

		# Convert ip addreseses to integers, so we can quantize them in order to compare
		ip = int(ipaddress.ip_address(IP))
		min_ip_int = int(ipaddress.ip_address(min_ip))
		max_ip_int = int(ipaddress.ip_address(max_ip))

		# See if IP address is in range
		if ip < min_ip_int or ip > max_ip_int:
			return False
		else:
			return True

	'''
	This function is used when the port entry in the dataframe is a range
	Detects whether port passed into accept_packet is in given range
	'''
	def port_in_range(self, port_range, port):
		min_port, max_port = port_range.split('-')
		min_port = int(min_port)
		max_port = int(max_port)

		port = int(port)
		if port < min_port or port > max_port:
			return False
		else:
			return True


	'''
	Given 4 fields, iterates through dataframe and detects if there exists a valid rule
	'''
	def accept_packet(self, direction, protocol, port, ip_address):
		# Iterate through each row of pandas df
		for index, row in self.df.iterrows():
			is_direction  = (row['direction'] == direction)
			is_protocol = (row['protocol'] == protocol)

			# If port is a range, then call port_in_range, otherwise use simple integer comparison
			if("-" in row['port']):
				is_port = self.port_in_range(row['port'], port)
			else:
				is_port = (int(row['port']) == port)

			# If ip_address is a range, then call ip_in_range, otherwise use simple string comparison
			if("-" in row['ip_address']):
				is_ip_address = self.ip_in_range(row['ip_address'], ip_address)
			else:
				is_ip_address = (row['ip_address'] == ip_address)

			# If all 4 fields match a rule, then return True
			if is_direction and is_protocol and is_port and is_ip_address:
				return True

		return False

