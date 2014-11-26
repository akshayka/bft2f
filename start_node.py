import sys
from bft2f_pb2 import *
from argparse import ArgumentParser
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from collections import namedtuple
import inspect

from threading import Timer

from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA 
from base64 import b64encode, b64decode

#constants
MULTICAST_ADDR = "228.0.0.5"
PORT = 8005
F = 2
VIEW_TIMEOUT = 2
CHECKPOINT_INTERVAL = 128
CacheEntry = namedtuple('CacheEntry', 'req rep')

class NodeState():
    NORMAL=1
    VIEW_CHANGE=2

class BFT2F_Node(DatagramProtocol):
    def __init__(self, node_id):
        self.node_id = node_id
        self.state = NodeState.NORMAL
        self.view = 0
        self.replay_cache = {}
        self.primary = 0 # h0 always starts as primary
        self.highest_accepted_n = 0

        # messages received directly from the client
        self.request_msgs = {}

        # map sequence number to single prepare msg
        #
        # the request carried by prepare for sequence number n must match
        # the request carried by pre_prepare_msgs[n]
        self.pre_prepare_msgs = {}

        # map sequence number to bag of prepare msgs
        #
        # we collect 2f + 1 prepares for each sequence number,
        # and we refer to this dictionary when constructing the set P during
        # a view change
        self.prepare_msgs = {}

        # map sequence number to bag of commit msgs
        #
        # a bag of 2f + 1 commit messages for a given sequence number provides
        # proof that the particular sequence number committed.
        self.commit_msgs = {}
        
        # hash chain digest history
        #
        # referred to when checking the fork set of a client's message,
        # and when checking domination ordering between two versions
        # during a view change
        self.T = [""]

        self.kv_store = {}
        self.client_addr = {}

        #Version init
        self.V = [None] * (3 * F + 1)
        #TODO what if it's restored from temporal outage?
        #I guess we may need some protocol to ask around using multicast -J
        for i in xrange(0, 3 * F + 1):
            self.V[i] = BFT2F_VERSION(node_id=i,
                                      view=self.view,
                                      n=self.highest_accepted_n,
                                      hcd="")
        # load private key
        key = open("./certs/server%d.key"%self.node_id, "r").read() 
        self.private_key = PKCS1_v1_5.new(RSA.importKey(key))

        key = open("./certs/rootCA_pub.pem", "r").read() 
        self.rootCA_pubkey = PKCS1_v1_5.new(RSA.importKey(key))

        #load public keys
        self.server_pubkeys=[]
        for i in xrange(0, 3 * F + 1):
            key = open("./certs/server%d.pem"%i, "r").read() 
            self.server_pubkeys.append(PKCS1_v1_5.new(RSA.importKey(key)))
        self.client_pubkeys=[]
        for i in xrange(0, 2):
            key = open("./certs/client%d.pem"%i, "r").read() 
            self.client_pubkeys.append(PKCS1_v1_5.new(RSA.importKey(key)))

    def change_view(self):
        print "timed out: %d"%self.view
        sys.stdout.flush()
        self.state=NodeState.VIEW_CHANGE
        #TODO send view change request
        self.timer = Timer(VIEW_TIMEOUT,self.change_view,args=[])
        self.timer.start()

    def startProtocol(self):
        """
        Called after protocol has started listening.
        """
        # Set the TTL>1 so multicast will cross router hops:
        self.transport.setTTL(5)
        # Join a specific multicast group:
        self.transport.joinGroup(MULTICAST_ADDR)
        print "started"
        sys.stdout.flush()

    def datagramReceived(self, datagram, address):
        msg = BFT2F_MESSAGE()
        msg.ParseFromString(datagram)

        #signature verification
        if msg.msg_type == BFT2F_MESSAGE.REQUEST:
            self.client_addr[msg.client_id]=address
            signer = self.client_pubkeys[msg.client_id]
        else:
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

        #TODO check node state.
        #If it's in view change, ignore everything other than new-view
        if self.state==NodeState.VIEW_CHANGE:
            if msg.msg_type == BFT2F_MESSAGE.NEW_VIEW:
                handle_new_view(self, msg, address)
            elif msg.msg_type == BFT2F_MESSAGE.VIEW_CHANGE:
                handle_view_change(self, msg, address)
            else:
                return
        if msg.msg_type == BFT2F_MESSAGE.REQUEST:
            print "Recieved a REQUEST"
            sys.stdout.flush()
            self.handle_request(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.PRE_PREPARE:
            print "Recieved a PRE_PREPARE"
            sys.stdout.flush()            
            self.handle_pre_prepare(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.PREPARE:            
            print "Recieved a PREPARE"
            sys.stdout.flush()
            self.handle_prepare(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.COMMIT:
            print "Recieved a COMMIT"
            self.handle_commit(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.VIEW_CHANGE:
            print "Recieved a VIEW_CHANGE"
        elif msg.msg_type == BFT2F_MESSAGE.NEW_VIEW:
            print "Recieved a NEW_VIEW"
        elif msg.msg_type == BFT2F_MESSAGE.CHECKPOINT:
            print "Recieved a CHECKPOINT"

        sys.stdout.flush()
        
    def handle_new_view(self, msg, address):
        pass
    def handle_view_change(self, msg, address):
        pass
    def handle_request(self, msg, address):
        last_rep_entry = self.replay_cache.get(msg.client_id)
        if last_rep_entry:
            if last_rep_entry.req.ts < msg.ts:
                return
            elif last_rep_entry.req.ts == msg.ts:
                self.send_msg(last_rep_entry.rep, address)
                return
            else:
                if last_rep_entry.rep.version != msg.version:
                    return

        if self.node_id == self.primary:
            print "handling"
            sys.stdout.flush()
            pp_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PRE_PREPARE,
                                            node_id=self.node_id,
                                            view=self.view,
                                            n=self.highest_accepted_n + 1,
                                            req_D=self.digest_func(msg.SerializeToString()),
                                            sig="")
            pp_msg.sig = self.sign_func(pp_msg.SerializeToString())
            self.send_multicast(pp_msg)
            print "sending"
            sys.stdout.flush()

        self.replay_cache[msg.client_id] = CacheEntry(req=msg, rep=None)
        self.request_msgs[self.digest_func(msg.SerializeToString())] = msg
        #start timeout for view change
        self.timer = Timer(VIEW_TIMEOUT,self.change_view,args=[])
        self.timer.start()

    def handle_pre_prepare(self, msg, address):
        #cancel timeout if any
        self.timer.cancel()

        if msg.req_D not in self.request_msgs or\
                self.view != msg.view or\
                msg.n > self.highest_accepted_n + 10 or\
                (self.pre_prepare_msgs.get(msg.n) != msg and\
                     self.pre_prepare_msgs.get(msg.n)):
            print "ignore"
            sys.stdout.flush()
            return;
        
        self.pre_prepare_msgs[msg.n] = msg
        p_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PREPARE,
                              node_id=self.node_id,
                              view=self.view,
                              n=msg.n,
                              req_D=msg.req_D,
                              sig="")
        p_msg.sig = self.sign_func(p_msg.SerializeToString())

        self.highest_accepted_n = msg.n
        self.send_multicast(p_msg)

        return

    def handle_prepare(self, msg, address):        
        if msg in self.prepare_msgs.setdefault(msg.n, []):
            return
        
        self.prepare_msgs[msg.n].append(msg)
        if len(self.prepare_msgs[msg.n]) == 2 * F + 1:
            r_msg = self.request_msgs[msg.req_D]
            self.T.append(self.digest_func(self.digest_func(r_msg.SerializeToString()) + self.T[-1]))
            self.V[self.node_id] = BFT2F_VERSION(node_id=self.node_id,
                                                 view=self.view,
                                                 n=msg.n,
                                                 hcd=self.T[-1])      
            c_msg = BFT2F_MESSAGE(node_id=self.node_id,
                                msg_type=BFT2F_MESSAGE.COMMIT,
                                version=self.V[self.node_id],
                                sig="")
            c_msg.sig=self.sign_func(c_msg.SerializeToString())
            self.send_multicast(c_msg)


    def handle_commit(self, msg, address):
        #TODO check if HCD is valid
        self.V[msg.version.node_id] = msg.version
        if len([v for v in self.V if self.versions_match(v, msg.version)]) == 2*F + 1:
            r_msg = self.request_msgs[self.pre_prepare_msgs[msg.version.n].req_D]
            res = self.execute_op(r_msg.op)
            client_id = r_msg.client_id
            rp_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.REPLY,
                                  client_id=r_msg.client_id,
                                  node_id=self.node_id,
                                  ts=r_msg.ts,
                                  res=res,
                                  version=self.V[msg.node_id],
                                  sig="")
            rp_msg.sig = self.sign_func(rp_msg.SerializeToString())
            self.replay_cache[r_msg.client_id]=rp_msg
            print "replying to %s %s" % (client_id, PORT)
            self.send_msg(rp_msg, self.client_addr[client_id])

    def execute_op(self, op):
        #TODO tokens
        if op.type == BFT2F_OP.PUT:
            self.kv_store[op.key] = op.val
        return self.kv_store[op.key]

    def versions_match(self, v1, v2):
        return (v1.view == v2.view) and (v1.n == v2.n) and (v1.hcd == v2.hcd)

    def send_msg(self, msg, address):
        self.transport.write(msg.SerializeToString(), address)

    def send_multicast(self, msg):
        self.transport.write(msg.SerializeToString(), (MULTICAST_ADDR, PORT))

    def digest_func(self, data):
        digest = SHA.new(data)
        return b64encode(digest.digest())

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
	parser = ArgumentParser()
	parser.add_argument('--node_id', '-n',
                            type=long,
                            required=True)
	args = parser.parse_args()

	reactor.listenMulticast(PORT, BFT2F_Node(args.node_id), listenMultiple=True)
	reactor.run()
if __name__ == '__main__':
	main()
