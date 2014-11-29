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
import cPickle

MULTICAST_ADDR = "228.0.0.5"
PORT = 8005
F = 2
VIEW_TIMEOUT = 2
CHECKPOINT_INTERVAL = 100
# must be greater than CHECKPOINT_INTERVAL
WATER_MARK_DELTA = CHECKPOINT_INTERVAL * 2

CacheEntry = namedtuple('CacheEntry', 'req rep')
Checkpoint = namedtuple('Checkpoint', 'kv_store hcd V replay_cache')
HistoryEntry = namedtuple('HistoryEntry', 'hcd matching_versions')
counter = 0

class NodeState():
    NORMAL=1
    VIEW_CHANGE=2


class BFT2F_Node(DatagramProtocol):
    # TODO J raises a good point below -- what if the node is coming up after
    # an outage? We'll have to run a protocol that allows this node to determine
    # the current state. -A
    # TODO should state be logged to disk? e.g. the message log.
    # PBFT uses memory-mapped files that are asynchronously written to disk -A
    def __init__(self, node_id):
        self.node_id = node_id
        self.state = NodeState.NORMAL
        self.view = 0
        self.replay_cache = {}

        # h0 always starts as primary
        # TODO change after (during?) view change -A
        self.primary = 0
        self.highest_accepted_n = 0

        # only accept prepare, commit messages with sequence numbers between
        # low_water_mark and high_water_mark
        #
        # invariant: low_water_mark == highest sequence number in last checkpoint
        self.low_water_mark = 0
        self.high_water_mark = self.low_water_mark + WATER_MARK_DELTA

        # TODO: Are we going to use these still? -A
        self.NO_OP_REQUEST = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.REQUEST,
                                           op=BFT2F_OP(type=BFT2F_OP.NO_OP, key='no_op'),
                                           sig='no_op')
        self.NO_OP_REQUEST_D = self.digest_func(self.NO_OP_REQUEST.SerializeToString())

        # messages received from clients
        #
        # TODO What if a malicious primary sends no_op requests,
        # even though no client sent them? Our replicas will see that they have
        # a no_op request in request_msgs, which might be a problem. -A
        # messages received directly from the client
        self.request_msgs = {self.NO_OP_REQUEST_D: self.NO_OP_REQUEST}

        # map sequence number to single pre_prepare msg
        #
        # the request carried by prepare for sequence number n must match
        # the request carried by pre_prepare_msgs[n]
        self.pre_prepare_msgs = {}

        # map sequence number to bag of prepare msgs
        #
        # we collect 2f + 1 prepares for each sequence number,
        # and we refer to this dictionary when constructing the set P during
        # a view change; only needs to contain uncommitted msgs
        self.prepare_msgs = {}

        # map sequence number to bag of commit msgs
        #
        self.commit_msgs = {}
        
        # augmented hash chain digest history
        #
        # referred to when checking the fork set of a client's message,
        # and when checking domination ordering between two versions
        # during a view change
        #
        # a bag of 2f + 1 commit messages for a given sequence number provides
        # proof that the particular sequence number committed -- here, each
        # version functions as a commit message
        #
        # used during view changes and fast-forwards
        self.T = {self.highest_accepted_n: HistoryEntry(hcd="", matching_versions=[])} # start with emtpy HCD
        self.kv_store = {}
        self.client_addr = {}

        # version vector init
        self.V = [None] * (3 * F + 1)
        self.view_change_msgs = []
        self.pending_view_change_msgs = {}

        #TODO what if it's retored from temporal outage?
        #I guess we may need some protocol to ask around using multicast -J
        for i in xrange(0, 3 * F + 1):
            self.V[i] = BFT2F_VERSION(node_id=i,
                                      view=self.view,
                                      n=self.highest_accepted_n,
                                      hcd="",
                                      sig="") # No need to sign empty version
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

        # map sequence number to pending checkpoint
        self.pending_checkpoints = {}

        # map sequence number to list of checkpoint proofs
        self.checkpoint_proofs = {}

    def change_view(self):
        print "timed out: %d"%self.V[self.node_id].view
        sys.stdout.flush()
        self.state=NodeState.VIEW_CHANGE
        #TODO send view change request
        P = []
        for n, pp_msg in self.pre_prepare_msgs.items():
            if n > self.V[self.node_id].n:
                if len(self.prepare_msgs.get(msg.n, [])) >= 2 * F + 1:
                    P.append([pp_msg] + self.prepare_msgs[n])        
        vh_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.VIEW_CHANGE,
                               node_id=self.node_id,
                               view=self.view + 1,
                               version=self.V[self.node_id],
                               P=P,
                               sig="")
        vh_msg.sig = self.sign_func(vh_msg.SerializeToString())
        self.send_multicast(vh_msg)
        # TODO in case there is another timer
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
        if self.node_id == 0 and self.highest_accepted_n > 0:
            return

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

        if msg.msg_type == BFT2F_MESSAGE.REQUEST and self.state == NodeState.Normal:
            print "Recieved a REQUEST"
            sys.stdout.flush()
            self.handle_request(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.PRE_PREPARE and self.state == NodeState.Normal:
            print "Recieved a PRE_PREPARE"
            sys.stdout.flush()            
            self.handle_pre_prepare(msg)
        elif msg.msg_type == BFT2F_MESSAGE.PREPARE and self.state == NodeState.Normal:
            print "Recieved a PREPARE"
            sys.stdout.flush()
            self.handle_prepare(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.COMMIT and self.state == NodeState.Normal:
            print "Recieved a COMMIT"
            self.handle_commit(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.VIEW_CHANGE:
            print "Recieved a VIEW_CHANGE"
            self.handle_view_change(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.NEW_VIEW:            
            print "Recieved a NEW_VIEW"
            self.handle_new_view(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.FAST_FORWARD_REQUEST:
            print "Recieved a FAST_FORWARD_REQUEST"
            self.handle_fast_forward_req(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.FAST_FORWARD_REPLY:
            print "Recieved a FAST_FORWARD_REPLY"
            self.handle_fast_forward_rep(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.CHECKPOINT:
            print "Recieved a CHECKPOINT"
            self.handle_checkpoint(msg, address)
        sys.stdout.flush()
        
    def handle_request(self, msg, address):
        #TODO check fork state 
        last_rep_entry = self.replay_cache.get(msg.client_id)
        if last_rep_entry and last_rep_entry.rep:
            if last_rep_entry.req.ts < msg.ts:
                return
            elif last_rep_entry.req.ts == msg.ts:
                self.send_msg(last_rep_entry.rep, address)
                return
            else:
                if last_rep_entry.rep.version != msg.version:
                    return

        if self.node_id == self.primary(self.view):
            print "handling"
            sys.stdout.flush()
            pp_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PRE_PREPARE,
                                            node_id=self.node_id,
                                            view=self.V[self.node_id].view,
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

    # pre_prepare: <node-id, view, n, D(msg_n)>
    def handle_pre_prepare(self, msg, address):
        #cancel timeout if any
        if self.node_id != self.primary():
            return

        if (not self.seqno_in_bounds(msg.n)) or\
           msg.req_D not in self.request_msgs or\
           self.view != msg.view or\
           (self.pre_prepare_msgs.get(msg.n) != msg and\
                self.pre_prepare_msgs.get(msg.n)):
            print "ignore"
            sys.stdout.flush()
            return;
        
        self.pre_prepare_msgs[msg.n] = msg
        p_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PREPARE,
                              node_id=self.node_id,
                              view=self.V[self.node_id].view,
                              n=msg.n,
                              req_D=msg.req_D,
                              sig="")
        p_msg.sig = self.sign_func(p_msg.SerializeToString())

        self.highest_accepted_n = msg.n
        self.send_multicast(p_msg)

        return

    # prepare: <node-id, view, n, D(msg_n)>
    def handle_prepare(self, msg):        
        if (not self.seqno_in_bounds(msg.n)) or\
           msg in self.prepare_msgs.setdefault(msg.n, []):
            return
        
        self.prepare_msgs[msg.n].append(msg)
        if len(self.prepare_msgs[msg.n]) == 2 * F + 1:
            r_msg = self.request_msgs[msg.req_D]
            new_hcd = self.digest_func(self.digest_func(r_msg.SerializeToString()) +\
                                           self.V[self.node_id].hcd)
            self.T[msg.n] = HistoryEntry(hcd=new_hcd, matching_versions=[])

            new_version = BFT2F_VERSION(node_id=self.node_id,
                                        view=self.V[self.node_id].view,
                                        n=msg.n,
                                        hcd=self.T[msg.n].hcd,
                                        sig="")
            new_version.sig = self.sign_func(new_version.SerializeToString())            
            self.V[self.node_id] = new_version

            c_msg = BFT2F_MESSAGE(node_id=self.node_id,
                                  msg_type=BFT2F_MESSAGE.COMMIT,
                                  version=new_version,
                                  sig="")
            c_msg.sig=self.sign_func(c_msg.SerializeToString())
            self.send_multicast(c_msg)

    # commit: < version-vector-entry >
    def handle_commit(self, msg, address):
        #TODO check if HCD is valid

        if not self.seqno_in_bounds(msg.version.n):
            return

        self.V[msg.version.node_id] = msg.version
        matching_versions = [v for v in self.V if self.versions_match(v, msg.version)]

        if self.versions_match(self.V[self.node_id], msg.version) and\
                len(matching_versions) == 2*F + 1:
            self.T[msg.n] = HistoryEntry(hcd=self.T[msg.n].hcd,
                                         matching_versions=matching_versions)
            r_msg = self.request_msgs[self.pre_prepare_msgs[msg.version.n].req_D]
            res = self.execute_op(r_msg.op)
            self.timer.cancel()
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

            # TODO According to the original paper, we generate
            # a checkpoint 'when a request with a sequence number divisible
            # by some constant is executed.' But what if the primary is an adversary
            # and always skips such sequence numbers? -A
            if msg.version.n % CHECKPOINT_INTERVAL == 0:
                self.make_checkpoint(msg.version.n)

    # TODO -A
    # checkpoint: < node-id, n, D(state), D(rcache) >
    def handle_checkpoint(self, msg, address):
        # collect 2f + 1 checkpoint messages for a given sequence number
        # these messages prove that a checkpoint is stable

        # Ignore if already stable
        if self.pending_checkpoints.get(n) and\
           len(self.checkpoint_proofs.setdefault(msg.n, [])) >= 2 * F + 1:
            return
        
        if not self.pending_checkpoints.get(n):
            self.checkpoint_proofs.setdefault(msg.n, []).append(msg)
        else:
            if msg.node_id == self.node_id:
               # TODO remove offending checkpoints
            # if valid message
            #   self.checkpoint_proofs.setdefault(msg.n, []).append(msg)
            # if 2F + 1
            #   save to disk
            #   truncate old state, forget old checkpoint
        pass

    def handle_view_change(self, msg, address):
        # IF node is new primary
        print msg

        if self.primary(msg.view) == self.node_id:
            if not self.valid_P(msg.P):
                return
            p_version = self.V[self.node_id]                        
            if self.valid_view_change(msg):
                self.update_view_change_state(msg)
            elif self.version_dominates(msg.version, p_version):
                self.request_fast_forward(address)
                self.pending_view_change_msgs[msg.node_id] = msg
            else:
                return #ignore

    def request_fast_forward(self, address):
        ff_req = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.FAST_FORWARD_REQUEST,
                               node_id=self.node_id,
                               version=self.V[self.node_id],
                               sig="")
        ff_req.sig = self.sign_func(ff_req.SerializeToString())
        self.send_msg(ff_req, address)
        

    def valid_view_change(self, msg):
        p_version = self.V[self.node_id]
        return self.version_dominates(p_version, msg.version) and\
            p_version.n in self.T and self.T[p_version.n].hcd == p_version.hcd and\
            msg.version.n in self.T and self.T[msg.version.n].hcd == msg.version.hcd

    def update_view_change_state(self, msg):
        self.view_change_msgs.append(msg)        
        if len(self.view_change_msgs) < 2 * F + 1:
            return

        V, O = self.generate_V_and_O(self.view_change_msgs)
        if(V and O)
            nv_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.NEW_VIEW,
                                   node_id=self.node_id,
                                   view=self.view + 1,
                                   version=self.V[selfnode_id],
                                   V=V,
                                   O=O.values(),
                                   sig="")
            nv_msg.sig = self.sign_func(nv_msg.SerializeToString())
            self.send_multicast(nv_msg)
            self.view = self.view + 1
            self.pending_view_change_msgs = {}
            self.view_change_msgs = []
            self.state=NodeState.Normal
            #TODO LOCK

    def generate_V_and_O(self, view_msgs):
        V = []
        O = {}
        for vc_msg in view_msgs:
            valid_vc_msg = True
            for P_m in msg.P:
                cur_pp_msg = P_em[0]                    
                new_pp_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PRE_PREPARE,
                                           node_id=self.node_id,
                                           view=vc_msg.view,
                                           n=cur_pp_msg.n,
                                           req_D=cur_pp_msg.req_d,
                                           sig="")
                new_pp_msg.sig = self.sign_func(new_pp_msg.SerializeToString())
                pp_msg = O.setdefault(cur_pp_msg.n, new_pp_msg)
                if pp_msg != new_pp_msg:
                    valid_vc_msg = False
                    break
            if valid_vc_msg:
                V.append(vc_msg)

        if len(V) >= 2 * F + 1:
            max_n = max(O.keys()) if len(O.keys()) > 0 else 0
            min_n = min(O.keys()) if len(O.keys()) > 0 else 0
            for n in range(min_n, max_n):
                if n not in O:                    
                    new_pp_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PRE_PREPARE,
                                               node_id=self.node_id,
                                               view=vc_msg.view,
                                               n=P_m[0].n,
                                               req_D=self.NO_OP_REQUEST_D,
                                               sig="")
                    new_pp_msg.sig = self.sign_func(new_pp_msg.SerializeToString())
                    O[n] = new_pp_msg
            return (V, O)
        else:
            return (None, None)

    def valid_P(self, P):
        for P_m in P:
            cur_pp_msg = P_em[0]
            unique_p_msgs = list(set(P_m[1:]))
            if(len(unique_p_msgs) < 2 * F + 1):
                return False            
            for u_p_msg in unique_p_msg:
                signer = self.server_pubkeys[u_p_msg.node_id]
                signature = u_p_msg.sig
                u_p_msg.sig = ""
                if not self.verify_func(signer, signature, u_p_msg.SerializeToString()):
                    return False
                if not self.equiv_prepares(u_p_msg, cur_pp_msg):
                    return False
        return True
        
    def handle_new_view(self, msg, address):
        if self.state == NodeState.Normal:
            self.state = NodeState.ViewChange            
        if self.node_id != self.primary(self.view + 1):
            return
        if not all(self.valid_P(vc_msg.P) for vc_msg in msg.V):
            return

        V, O = self.generate_V_and_O(self.view_change_msgs)
        if V != msg.V:
            return
        
        if len(O) != len(msg.O):
            return

        for pp_msg in msg.O:
            if not equiv_prepares(O.get(pp_msg.n), pp_msg):
                return

        if self.version_dominates(msg.version, self.V[self.node_id]):
            self.pending_new_view_msgs.append(msg)
            self.request_fast_forward(address)
            return

        self.process_new_view(msg)

    def process_new_view(self, msg):
        self.view = msg.view
        self.timer.cancel()
        self.state=NodeState.Normal
        sorted_pp_msgs = sorted(msg.O, key=lambda pp_msg: pp_msg.n)
        for pp_msg in sorted_pp_msgs:
            if self.V[self.node_id].n >= pp_msg.n:
                continue
            self.handle_pre_prepare(pp_msg)
        
    def equiv_prepares(self, pp_msg_1, pp_msg_2):        
        return pp_msg_1 and pp_msg2 and\
            pp_msg_1.n == pp_msg_2.n and\
            pp_msg_1.view == pp_msg_2.view and\
            pp_msg_1.req_D == pp_msg_2.req_D

    def handle_fast_forward_req(self, msg, address):
        req_proofs = []
        r_version = self.V[self.node_id]        
        if self.version_dominates(r_version, msg.version) and\
                r_version.n in self.T and self.T[n_version.n].hcd == r_version.hcd and\
                msg.version.n in self.T and self.T[msg.version.n].hcd == msg.version.hcd:
            for i in range(msg.version.n + 1, r_version.n+ 1):
                r_msg = self.request_msgs[self.pre_prepare_msgs[i].req_D]
                req_proofs.append(BFT2F_REQUEST_PROOF(req=r_msg,
                                                      matching_versions=self.T[i].matching_versions))

        ff_rep_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.FAST_FORWARD_REPLY,
                                   node_id=self.node_id,
                                   req_proofs=req_proofs,
                                   sig="")
        ff_rep_msg.sig = self.sign_func(ff_rep_msg.SerializeToString())
        self.send_msg(ff_rep_msg, address)

    def handle_fast_forward_rep(self, msg, address):
        for rp in msg.req_proofs:
            if self.valid_req_proof(rp):
                self.T[self.node_id] = HistoryEntry(hcd=rp.matching_versions[0].hcd,
                                                    matching_versions=rp.matching_versions)
                self.V[self.node_id] = BFT2F_VERSION(node_id=self.node_id,
                                                     view=rp.matching_versions[0].view,
                                                     n=rp.matching_versions[0].n,
                                                     hcd=self.T[msg.n].hcd)
                self.execute_op(rp.req.op)
            else:
                #break if invalid req_proof
                break
        if msg.node_id in self.pending_view_change_msgs:            
            self.handle_view_change(self.pending_view_change_msgs[msg.node_id], address)

    def valid_req_proof(self, req_proof):
        # 2*F+1 unique versions
        unique_versions = list(set(req_proof.matching_versions))
        if len(unique_versions) < 2 * F + 1:
            return False
        # TODO check sig
        new_v = unique_versions[0]
        if not self.version_dominates(new_v, self.V[self.node_id]):
            return False
        
        for v in unique_versions:
            # Verify that versions match
            if not self.versions_match(v, new_v):
                return False

            # Verify version
            signer = self.server_pubkeys[v.node_id]
            signature = v.sig
            v.sig = ""
            if not self.verify_func(signer, signature, v.SerializeToString()):
                return False

            # Verify HCD
            new_hcd = self.digest_func(self.digest_func(req_proof.req.SerializeToString()) +\
                                           self.V[self.node_id].hcd)
            if new_hcd != new_v.hcd:
                return False

        return True

    def version_dominates(self, v1, v2):
        return v1.view >= v2.view and\
            ((v1.n == v2.n and v1.hcd == v2.hcd) or v1.n > v2.n)

    def execute_op(self, op):
        #TODO tokens
        if op.type == BFT2F_OP.PUT:
            self.kv_store[op.key] = op.val
        return self.kv_store[op.key]

    def make_checkpoint(self, n):
        hcd_n = self.T[n]
        self.pending_checkpoints[n] = Checkpoint(kv_store=self.kv_store,
                                                 hcd=hcd_n,
                                                 V=self.V,
                                                 replay_cache=self.replay_cache)
        ck_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.CHECKPOINT,
                              node_id=self.node_id,
                              n=n,
                              state_D=self.digest_func(str(self.kv_store) + hcd_n),
                              replay_cache_D=self.digest_func(str(self.replay_cache)),
                              sig="")
        ck_msg.sig = self.sign_func(ck_msg.SerializeToString())
        self.send_multicast(ck_msg)

    def seqno_in_bounds(self, n):
        return n >= self.low_water_mark and n <= self.high_water_mark

    def versions_match(self, v1, v2):
        return (v1.view == v2.view) and (v1.n == v2.n) and (v1.hcd == v2.hcd)

    def versions_list_match(self, versions):        
        for v in verions:
            if not versions_match(v, versions[0]):
                return False
        return True
        
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

    def primary(self, view):
        return view % (3 * F + 1)

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
