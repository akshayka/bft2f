import sys
from bft2f_pb2 import *

from argparse import ArgumentParser
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor


class BFT2F_Client(DatagramProtocol):

    def startProtocol(self):
        # Join the multicast address, so we can receive replies:
        self.transport.joinGroup("228.0.0.5")
        # Send to 228.0.0.5:8005 - all listeners on the multicast address
        # (including us) will receive this message.
        # send commit
        msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PUT_REQUEST,
                            op="oop",
                            ts=1,
                            client_id='10',
                            version=BFT2F_VERSION(node_id='10', view=1, n=1, hcd=""),
                            sig='sig')
        print len(msg.SerializeToString())
        print msg.SerializeToString()
        sys.stdout.flush()

        self.transport.write(msg.SerializeToString(), ("228.0.0.5", 8005))
        sys.stdout.flush()

    def datagramReceived(self, datagram, address):
        print "Datagram %s received from %s" % (repr(datagram), repr(address))
        msg = BFT2F_MESSAGE()
        msg.ParseFromString(datagram)




def main():
	parser = ArgumentParser()
	parser.add_argument('--dest_addr', '-da',
			    type=str,
			    required=False)
	args = parser.parse_args()
        print "start client"
        sys.stdout.flush()

	reactor.listenMulticast(8005, BFT2F_Client(), listenMultiple=True)
	reactor.run()

if __name__ == '__main__':
	main()
