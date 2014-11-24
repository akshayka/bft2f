import sys
from  bft2f_pb2 import *
from argparse import ArgumentParser
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from collections import namedtuple
import inspect

CacheEntry = namedtuple('CacheEntry', 'req rep')
MULTICAST_ADDR = "228.0.0.5"
PORT = 8005
F = 7


class BFT2F_Node(DatagramProtocol):
    def __init__(self, node_id):
        self.node_id = node_id
        self.view = 0
        self.ReplayCache = {}
        self.primary = '0' # h0 always starts as primary
        self.highest_accepted_n = 0
        self.put_request_msgs = {}
        self.pre_prepare_msgs = {}
        self.prepare_msgs = {}
        self.T = [""] # start with emtpy HCD

    def startProtocol(self):
        """
        Called after protocol has started listening.
        """
        # Set the TTL>1 so multicast will cross router hops:
        self.transport.setTTL(5)
        # Join a specific multicast group:
        self.transport.joinGroup("228.0.0.5")
        print "started"
        sys.stdout.flush()

    def datagramReceived(self, datagram, address):
        msg = BFT2F_MESSAGE()
        msg.ParseFromString(datagram)

        #if not self.verify_sig(msg.sig):
        #    return
        if msg.msg_type == BFT2F_MESSAGE.PUT_REQUEST:
            print "Recieved a PUT_REQUEST"
            sys.stdout.flush()
            self.handle_put_request(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.GET_REQUEST:
            print "Recieved a GET_REQUEST"
        elif msg.msg_type == BFT2F_MESSAGE.PRE_PREPARE:
            print "Recieved a PRE_PREPARE"
        elif msg.msg_type == BFT2F_MESSAGE.PREPARE:
            print "Recieved a PREPARE"
        elif msg.msg_type == BFT2F_MESSAGE.COMMIT:
            print "Recieved a COMMIT"
        elif msg.msg_type == BFT2F_MESSAGE.VIEW_CHANGE:
            print "Recieved a VIEW_CHANGE"
        elif msg.msg_type == BFT2F_MESSAGE.NEW_VIEW:
            print "Recieved a NEW_VIEW"
        elif msg.msg_type == BFT2F_MESSAGE.CHECKPOINT:
            print "Recieved a CHECKPOINT"

        sys.stdout.flush()
        
    def handle_put_request(self, msg, address):
        last_rep_entry = self.ReplayCache.get(msg.client_id)
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
                                            req_D=self.digest_func(msg))
            pp_msg.sig = self.sig_func(pp_msg)
            print "sending"
            sys.stdout.flush()
            self.send_multicast(pp_msg)
            print "sending"
            sys.stdout.flush()


        self.ReplayCache[msg.client_id] = CacheEntry(req=msg, rep=None)
        self.put_request_msgs[self.digest_func(msg)] = msg

    def handle_pre_prepare(self, msg, address):
        if self.digest_func(msg.msg) not in self.read_write_msgs or\
                self.view != msg.view or\
                self.msg.n > self.highest_accepted_n + 10 or\
                self.pre_prepare_msgs.get(msg.n) != msg:
           #ignore
           return;

        self.pre_prepare_msgs[msg.n] = msg
        p_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PREPARE,
                              node_id=self.node_id,
                              view=self.view,
                              n=msg.n,
                              req_D=msg.req_D)
        p_msg.sig = self.sig_func(p_msg)

        self.highest_accepted_n = msg.n
        self.send_multicast(p_msg)

        return

    def handle_prepare(self, msg, address):        
        if msg in self.prepare_msgs.setdefault(msg.n, []):
            return
        
        self.prepare_msgs[msg.n].append(msg)
        if len(self.prepare_msgs[msg.n]) >= 2 * F + 1:
            pr_msg = self.put_request_msgs[msg.req_D]
            self.T.append(self.digest_func(self.digest_func(pr_msg) + self.T[-1]))
            self.V[self.node_id] = BFT2F_VERSION(node_id=self.node_id,
                                                 view=self.view,
                                                 n=msg.n,
                                                 hcd=self.T[-1])      
            c_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.COMMIT,
                                  version=self.V[self.node_id])

            c_msg.sig=self.sig_func(c_msg)
            self.send_multicast(c_msg)


    def handle_commit(self, msg, address):
        #TODO check if HCD is valid
        self.V[msg.node_id] = msg.version
        all_versions = self.V.values()
        if len([v for v in all_versions if versions_match(v, msg.version)]) > 2*F + 1:
            pr_msg = self.put_request_msgs[self.pre_prepare_msgs[msg.version.n]]
            #execute
            print pr_msg.op
            r_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.REPLY,
                                  client_id=pr_msg.client_id,
                                  ts=pr_msg.ts,
                                  res='res',
                                  version=self.V[msg.node_id])
            r_msg.sig = self.sig_func(r_msg)
            self.ReplayCache[pr_msg.client_id]=r_msg
            self.send_multicast(r_msg)

    def versions_match(v1, v2):
        return (v1.view == v2.view) and (v1.n == v2.n) and (v1.hcd == v2.hcd)

    def send_msg(self, msg, address):
        self.transport.write(msg.SerializeToString(), address)

    def send_multicast(self, msg):
        self.transport.write(msg.SerializeToString(), (MULTICAST_ADDR, PORT))

    def digest_func(self, data):
        return 'digest'

    def sig_func(self, msg):
        return 'sig'

# We use listenMultiple=True so that we can run MulticastServer.py and
# MulticastClient.py on same machine:

def main():
	parser = ArgumentParser()
	parser.add_argument('--node_id', '-n',
                            type=int,
                            required=False)
	args = parser.parse_args()

	reactor.listenMulticast(PORT, BFT2F_Node(str(args.node_id)), listenMultiple=True)
	reactor.run()

if __name__ == '__main__':
	main()
