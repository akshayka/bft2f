import sys, glob
sys.path.append('gen-py')
from auth_service import Auth_Service
from auth_service.ttypes import *

from bft2f_pb2 import *

from argparse import ArgumentParser
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from time import sleep, time

from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA 
from base64 import b64encode, b64decode
import threading

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer


MULTICAST_ADDR = "228.0.0.5"
BFT2F_PORT = 8005
USER_PORT = 9090
F = 2

parser = ArgumentParser()
parser.add_argument('--client_id', '-ci',
                    type=long,
                    required=True)
args = parser.parse_args()
print "start client"
sys.stdout.flush()

USER_REQUESTS = {}


class Auth_Service_Handler:
    def ping(self):
        print "ping"
        sys.stdout.flush()

    def sign_in(self, user_id, token):
        req_id = user_id + token
        USER_REQUESTS[req_id] = [threading.Event(), []]

        twisted_client.bft2f_sign_in(user_id, token)
        USER_REQUEST[req_id][0].wait()
        
        reps = USER_REQUEST[req_id][1]
        sign_in_certs = [rep.sign_in_cert for rep in reps]
        
        res = Auth_Service_Sign_In_Res(user_id=user_id,
                                       user_pub_key=reps[0].res.user_pub_key,
                                       user_priv_key_enc=reps[0].res.user_priv_key_enc,
                                       sign_in_certs=sign_in_certs)
        print res

    def sign_up(self, user_id, user_pub_key, user_priv_key_enc):
        req_id = user_id
        USER_REQUESTS[req_id] = [threading.Event(), []]
        # Make a call to bft2f
        twisted_client.bft2f_sign_up(user_id, user_pub_key, user_priv_key_enc)
        
        # Wait untill bft2f comes up with a response(2f + 1)
        USER_REQUESTS[req_id][0].wait()
        return Auth_Service_Sign_In_Res(user_id=user_id,
                                        user_pub_key=user_pub_key,
                                        user_priv_key_enc=user_priv_key_enc)


class BFT2F_Client(DatagramProtocol):
    def __init__(self, client_id):
        self.client_id = client_id
        # load private key
        key = open("./certs/client%d.key"%self.client_id, "r").read() 
        self.private_key = PKCS1_v1_5.new(RSA.importKey(key))

        key = open("./certs/rootCA_pub.pem", "r").read() 
        self.rootCA_pubkey = PKCS1_v1_5.new(RSA.importKey(key))

        self.version = BFT2F_VERSION(node_id=0, view=0, n=0, hcd="")

        self.ts = 0

        #load public keys
        self.server_pubkeys=[]
        for i in xrange(0, 3 * F + 1):
            key = open("./certs/server%d.pem"%i, "r").read() 
            self.server_pubkeys.append(PKCS1_v1_5.new(RSA.importKey(key)))

        self.user_conn_mapping = {}


    def startProtocol(self):
        pass

    def bft2f_sign_up(self, user_id, user_pub_key, user_priv_key_enc):
        msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.REQUEST,
                            op=BFT2F_OP(type=SIGN_UP,
                                        user_id=user_id,
                                        user_pub_key=user_pub_key,
                                        user_priv_key_enc=user_priv_key_enc),
                            ts=1,
                            client_id=self.client_id,
                            version=self.version,
                            sig='')
        msg.sig = self.sign_func(msg.SerializeToString())
        self.transport.write(msg.SerializeToString(), (MULTICAST_ADDR, BFT2F_PORT))

    def bft2f_sign_in(self, user_id, token):
        print "thrift sign in"
        msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.REQUEST,
                            op=BFT2F_OP(type=SIGN_IN, user_id=user_id, token=token),
                            ts=self.make_ts(),
                            client_id=self.client_id,
                            version=self.version,
                            sig='')
        msg.sig = self.sign_func(msg.SerializeToString())
        self.transport.write(msg.SerializeToString(), (MULTICAST_ADDR, BFT2F_PORT))

    def datagramReceived(self, datagram, address):
        print "Datagram %s received from %s" % (repr(datagram), repr(address))
        msg = BFT2F_MESSAGE()
        msg.ParseFromString(datagram)
        signer = self.server_pubkeys[msg.node_id]
        signature = msg.sig
        msg.sig = ""
        if not self.verify_func(signer,signature,msg.SerializeToString()):
            print "wrong signature : %d :" % msg.node_id, msg.msg_type
            sys.stdout.flush()
            return
        else:
            print "valid signature"
            sys.stdout.flush()

        if msg.res.type != BFT2f_OP_RES.SUCCESS:
            print "not success"
            sys.stdout.flush()

            return
        
        if msg.op.type == SIGN_UP:
            req_id = msg.res.user_id + msg.res.token
        elif msg.op.type == SIGN_IN:
            req_id = msg.user_id
            
        USER_REQUESTS[req_id][1].append(msg)

        matching_reps = self.matching_reps(USER_REQUESTS[req_id][1], msg)
        print len(matching_reps)
        sys.stdout.flush()

        if len(matching_reps) >= 2 * F + 1:
            self.version = msg.version
            USER_REQUESTS[req_id][1] = matching_reps
            USER_REQUESTS[req_id][0].set()

        return

    def matching_reps(self, reps, new_rep):
        matching_reps = []
        unique_nodes = set()

        for r in reps:
            if (r.res.type == new_rep.res.type and\
                r.res.user_pub_key == new_rep.res.user_pub_key and\
                r.res.user_priv_key_enc == new_rep.res.user_priv_key_enc and\
                r.node_id not in unique_nodes):
                unique_nodes.add(r.node_id)
                matching_reps.append(r)

        return matching_reps
        
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

    def make_ts(self):
        ret = self.ts
        self.ts = self.ts + 1
        return ret

def start_twisted():
    reactor.listenMulticast(BFT2F_PORT, twisted_client, listenMultiple=True)
    print "start twisted"
    reactor.run(installSignalHandlers=0)
    

def start_thrift():
    processor = Auth_Service.Processor(thrift_handler)
    transport = TSocket.TServerSocket(port=USER_PORT)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()
    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
    print "start thrit"
    server.serve()


thrift_handler = Auth_Service_Handler()
twisted_client = BFT2F_Client(args.client_id)


if __name__ == '__main__':
    twisted_thread = threading.Thread(target=start_twisted)
    twisted_thread.start()
    thrift_thread = threading.Thread(target=start_thrift)
    thrift_thread.start()
