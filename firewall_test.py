import firewall
import unittest


class TestStringMethods(unittest.TestCase):

	def test_cases(self):
		fw = firewall.Firewall("firewall_data.csv")

		self.assertTrue(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
		self.assertTrue(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
		
		self.assertTrue(fw.accept_packet("inbound", "udp", 1001, "1.1.1.1"))
		self.assertTrue(fw.accept_packet("outbound", "tcp", 70, "78.32.170.4"))
		self.assertTrue(fw.accept_packet("inbound", "tcp", 68, "10.0.0.8"))

		self.assertFalse(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
		self.assertFalse(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))

		self.assertFalse(fw.accept_packet("inbound", "udp", 1001, "255.255.255.255"))
		self.assertFalse(fw.accept_packet("outbound", "tcp", 71, "78.32.170.4"))
		self.assertFalse(fw.accept_packet("inbound", "udp", 68, "10.0.0.8"))
		self.assertFalse(fw.accept_packet("inbound", "udp", 53, "192.168.1.0"))


if __name__== "__main__":
	unittest.main()