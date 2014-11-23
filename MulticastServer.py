from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import socket

class MulticastPingPong(DatagramProtocol):

    def startProtocol(self):
        """
        Called after protocol has started listening.
        """
        # Set the TTL>1 so multicast will cross router hops:
        self.transport.setTTL(5)
        # Join a specific multicast group:
        self.transport.joinGroup("228.0.0.5")
        #self.transport.joinGroup("224.0.0.1")

    def datagramReceived(self, datagram, address):
        print "Datagram %s received from %s" % (repr(datagram), repr(address))
        if datagram == "Client: Ping":
            # Rather than replying to the group multicast address, we send the
            # reply directly (unicast) to the originating port:
            self.transport.write("Server: Pong", address)
        exit()


# We use listenMultiple=True so that we can run MulticastServer.py and
# MulticastClient.py on same machine:
print "Starting server"
reactor.listenMulticast(8005, MulticastPingPong(), listenMultiple=True)
reactor.run()
