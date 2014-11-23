from argparse import ArgumentParser
import socket
import sys

def main():
	parser = ArgumentParser()
	parser.add_argument('--dest_addr', '-da',
						type=str,
						required=True)
	args = parser.parse_args()
	print args
	HOST, PORT = args.dest_addr, 9090
	data = 'hello'

	# SOCK_DGRAM is the socket type to use for UDP sockets
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# Enable broadcasts
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

	try:
		sock.sendto(data + '\n', (HOST, PORT))
	except IOError as e:
		print 'I/O error({0}): {1}'.format(e.errno, e.strerror)
		sys.stdout.flush()
		return

	print 'Sent: {}'.format(data)
	sys.stdout.flush()

if __name__ == '__main__':
	main()
