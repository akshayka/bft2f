import sys
from bft2f_pb2 import *

from argparse import ArgumentParser
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from time import sleep, time

MULTICAST_ADDR = "228.0.0.5"
PORT = 8005

parser = ArgumentParser()
parser.add_argument('--client_id', '-ci',
                    type=str,
                    required=False)
args = parser.parse_args()
print "start client"
sys.stdout.flush()

class BFT2F_Client(DatagramProtocol):

    def startProtocol(self):
        # Join the multicast address, so we can receive replies:
        #self.transport.joinGroup("228.0.0.5")
        # Send to 228.0.0.5:8005 - all listeners on the multicast address
        # (including us) will receive this message.
        # send commit
        sleep(25)
        print "send again"
        sys.stdout.flush()
        self.transport.write(msg.SerializeToString(), (MULTICAST_ADDR, PORT))

        
        
        sys.stdout.flush()

    def bft2f_put(self, key, val):
        msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.REQUEST,
                            op=BFT2F_OP(type=BFT2F_OP.PUT, key=key, val=val),
                            ts=1,
                            client_id=args.client_id,
                            version=BFT2F_VERSION(node_id=0, view=0, n=0, hcd="", sig=""),
                            sig='sig')
        print "send"
        sys.stdout.flush()
        self.transport.write(msg.SerializeToString(), (MULTICAST_ADDR, PORT))

    def bft2f_get(self, key):

    def datagramReceived(self, datagram, address):
        #print "Datagram %s received from %s" % (repr(datagram), repr(address))
        msg = BFT2F_MESSAGE()
        msg.ParseFromString(datagram)
        print msg.res
        sys.stdout.flush()



def main():
	reactor.listenMulticast(8005, BFT2F_Client(), listenMultiple=True)
	reactor.run()

if __name__ == '__main__':
	main()
