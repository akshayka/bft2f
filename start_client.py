import sys
from bft2f_pb2 import *

from argparse import ArgumentParser
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from time import sleep, time

from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA 
from base64 import b64encode, b64decode

MULTICAST_ADDR = "228.0.0.5"
PORT = 8005
F = 2

parser = ArgumentParser()
parser.add_argument('--client_id', '-ci',
                    type=long,
                    required=True)
args = parser.parse_args()
print "start client"
sys.stdout.flush()

class BFT2F_Client(DatagramProtocol):
    def __init__(self, client_id):
        self.client_id = client_id
        # load private key
        key = open("./certs/client%d.key"%self.client_id, "r").read() 
        self.private_key = PKCS1_v1_5.new(RSA.importKey(key))

        key = open("./certs/rootCA_pub.pem", "r").read() 
        self.rootCA_pubkey = PKCS1_v1_5.new(RSA.importKey(key))

        #load public keys
        self.server_pubkeys=[]
        for i in xrange(0, 3 * F + 1):
            key = open("./certs/server%d.pem"%i, "r").read() 
            self.server_pubkeys.append(PKCS1_v1_5.new(RSA.importKey(key)))

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
                            client_id=self.client_id,
                            version=BFT2F_VERSION(node_id=0, view=0, n=0, hcd=""),
                            sig='')
        msg.sig = self.sign_func(msg.SerializeToString())
        self.transport.write(msg.SerializeToString(), (MULTICAST_ADDR, PORT))

    def bft2f_get(self, key):

    def datagramReceived(self, datagram, address):
        #print "Datagram %s received from %s" % (repr(datagram), repr(address))
        msg = BFT2F_MESSAGE()
        msg.ParseFromString(datagram)

        #msg verification
        signer = self.server_pubkeys[msg.node_id]
        signature = msg.sig
        msg.sig = ""
        if not self.verify_func(signer,signature,msg.SerializeToString()):
            print "wrong signature : %d :"%msg.node_id, msg.msg_type
            sys.stdout.flush()
            return
        else:
            print "valid signature"
            sys.stdout.flush()

        print msg.res
        sys.stdout.flush()

    def verify_func(self, signer, signature, data):
        digest = SHA.new(data) 
        if signer.verify(digest, b64decode(signature)):
            return True
        return False

    def sign_func(self, data):
        #return ""
        digest = SHA.new(data)
        sign = self.private_key.sign(digest) 
        return b64encode(sign)


def main():
	reactor.listenMulticast(8005, BFT2F_Client(args.client_id), listenMultiple=True)
	reactor.run()

if __name__ == '__main__':
	main()
