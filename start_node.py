import sys, glob

sys.path.append('gen-py')

import json
import socket
from bft2f import BFT2F_NODE
from bft2f.ttypes import *

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

from argparse import ArgumentParser
from multiprocessing import Process
from time import sleep, time

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import SocketServer

parser = ArgumentParser()


parser.add_argument('--rep-addrs', '-ra',
                    type=str,
                    required=False)
parser.add_argument('--name', '-n',
                    type=int,
                    required=False)

args = parser.parse_args()
name = None
rep_addrs = {}

rep_addrs = eval(args.rep_addrs)
class MyUDPHandler(SocketServer.BaseRequestHandler):
    """
    This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection the client address must be given explicitly
    when sending data back via sendto().
    """

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print "Recieved " + str(data)
        sys.stdout.flush()

if __name__ == "__main__":
    HOST = rep_addrs[args.name]
    PORT = 9090
    server = SocketServer.UDPServer((HOST, PORT), MyUDPHandler)
    print "Start"
    sys.stdout.flush()

    server.serve_forever()

'''

class Echo(DatagramProtocol):

    def startProtocol(self):
        self.transport.setBroadcastAllowed(True)

    def datagramReceived(self, data, (host, port)):
        print "received %r from %s:%d" % (data, host, port)
        sys.stdout.flush()
        self.transport.write(data + "i am %d" % (args.name), (host, port))

reactor.listenUDP(9090, Echo())
print "started node"
sys.stdout.flush()
reactor.run()


class MulticastPingPong(DatagramProtocol):

    def startProtocol(self):
        """
        Called after protocol has started listening.
        """
        # Set the TTL>1 so multicast will cross router hops:
        print "started %d" % (args.name)
        #self.transport.setTTL(5)
        # Join a specific multicast group:
        #self.transport.joinGroup("228.0.0.5")

    def datagramReceived(self, datagram, address):
        print "Datagram %s received from %s" % (repr(datagram), repr(address))
        sys.stdout.flush()
        if datagram == "Client: Ping":
            # Rather than replying to the group multicast address, we send the
            # reply directly (unicast) to the originating port:
            self.transport.write("Server: Pong", address)


# We use listenMultiple=True so that we can run MulticastServer.py and
# MulticastClient.py on same machine:
print "started"
sys.stdout.flush()
reactor.listenUDP(9090, MulticastPingPong())
print "oops"
sys.stdout.flush()

reactor.run()

print "run"
sys.stdout.flush()
'''
