import sys, glob
import traceback

import json
import socket

from argparse import ArgumentParser
from multiprocessing import Process
from time import sleep, time
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

parser = ArgumentParser()


parser.add_argument('--dest-addr', '-da',
                    type=str,
                    required=True)

args = parser.parse_args()

print args


HOST, PORT = args.dest_addr, 9090
data = "hello"

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

# As you can see, there is no connect() call; UDP has no connections.
# Instead, data is directly sent to the recipient via sendto().
sock.sendto(data + "\n", (HOST, PORT))

print "Sent:     {}".format(data)
sys.stdout.flush()



'''

class EchoClient(DatagramProtocol):

    def startProtocol(self):
        self.transport.setBroadcastAllowed(True)
        data = "hello"
        host = args.dest_addr
        port = 9090

        print "sent %r from client to %s:%d" % (data, host, port)
        try:
            self.transport.write(data, (host, port))
        except Exception, err:
            print traceback.format_exc()

        print "done sent"
        sys.stdout.flush()


reactor.listenUDP(9090, EchoClient())
print "started client"
sys.stdout.flush()
reactor.run()



class MulticastPingClient(DatagramProtocol):

    def startProtocol(self):
        # Join the multicast address, so we can receive replies:
        #self.transport.joinGroup(args.dest_addr)
        # Send to 228.0.0.5:8005 - all listeners on the multicast address
        # (including us) will receive this message.
        print "send ping %s " % (args.dest_addr)
        #try:
        self.transport.write('Client: Ping', (args.dest_addr, 9090))
        #except:
        #    print "shit"
        #   print "Unexpected error:", sys.exc_info()[0]
            
    
        print "done sending"
        sys.stdout.flush()
    def datagramReceived(self, datagram, address):
        print "Datagram %s received from %s" % (repr(datagram), repr(address))
        sys.stdout.flush()


reactor.listenUDP(9090, MulticastPingClient())

reactor.run()

'''
