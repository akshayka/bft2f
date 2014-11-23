from argparse import ArgumentParser
import socket
import SocketServer
import sys

addr = ''
class MyUDPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		data = self.request[0].strip()
		socket = self.request[1]
		global addr
		print '%s recieved %s' % (addr, str(data))
		sys.stdout.flush()


def main():
	parser = ArgumentParser()
	parser.add_argument('--rep_addr', '-ra',
						type=str,
						required=True)
	parser.add_argument('--name', '-n',
						type=int,
						required=False)
	args = parser.parse_args()
	global addr
	addr = args.rep_addr
	PORT = 9090
	server = SocketServer.UDPServer(('', PORT), MyUDPHandler)
	print 'Started node %s' % addr
	sys.stdout.flush()
	server.serve_forever()


if __name__ == '__main__':
	main()
