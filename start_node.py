import sys
from bft2f_pb2 import *
from argparse import ArgumentParser
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from collections import namedtuple

from threading import Lock, Timer

from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA 
from base64 import b64encode, b64decode

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
UserStoreEntry = namedtuple('UserStoreEntry', 'user_pub_key user_priv_key_enc')

class NodeState():
    NORMAL=1
    VIEW_CHANGE=2

class BFT2F_Node(DatagramProtocol):
    def __init__(self, node_id, verbose):
        self.lock = Lock()
        self.verbose = verbose
        self.node_id = node_id
        self.state = NodeState.NORMAL

        # NB: If this node is coming up after a failure and has
        # fallen behind, then it won't be able to execute operations.
        # The first client request it receives will cause it to time
        # out, triggering a view change that will bring it up to date.
        self.view = 0

        # highest sequence number for which a pre-prepare was accepted
        self.highest_accepted_n = 0

        # highest commited sequence number that
        self.highest_committed_n = 0

        # map client-id to most recently sent reply
        self.replay_cache = {}

        # only accept prepare, commit messages with sequence numbers between
        # low_water_mark and high_water_mark
        #
        # invariant: low_water_mark == highest sequence number in last checkpoint
        # TODO: Remove these if we do not finish the checkpoint implementation
        self.low_water_mark = 0
        self.high_water_mark = self.low_water_mark + WATER_MARK_DELTA

        # TODO: Are we going to use these still? -A
        self.NO_OP_REQUEST = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.REQUEST,
                                           op=BFT2F_OP(type=NO_OP, user_id='no_op'),
                                           sig='no_op')
        self.NO_OP_REQUEST_D = self.make_digest(self.NO_OP_REQUEST.SerializeToString())

        # messages received from clients
        #
        # TODO What if a malicious primary sends no_op requests,
        # even though no client sent them? Our replicas will see that they have
        # a no_op request in request_msgs, which might be a problem. -A
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

        # map user id to public, private key pair
        self.user_store = {}

        # map client id to IP address
        self.client_addr = {}

        # timer to trigger view changes
        #
        # timer is None if and only if this replica is not waiting for a
        # request to complete, where 'waiting' is as defined in the original
        # PBFT paper
        self.timer = None

        # messages collected by primary during a view change
        self.view_change_msgs = []

        # messages to which the primary is fast forwarding
        #
        # pending messages are only processed after fast forwarding is complete
        self.pending_view_change_msgs = {}

        # version vector
        #
        # Consists of 3F + 1 tuples: <node_id, view, n, hcd>
        self.V = [None] * (3 * F + 1)
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

        # load other replicas' public keys
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
        """
        Initiate a view change by multicasting a view-change message.
        Triggered by a timer time-out.
        """
        self.lock.acquire()
        self.printv("timed out: %d" % self.V[self.node_id].view)
        self.state=NodeState.VIEW_CHANGE
        P = []

        # Collect all messages that are prepared but not committed
        # These messages will be retried in the new view
        for n, pp_msg in self.pre_prepare_msgs.items():
            if n > self.V[self.node_id].n and\
               len(self.prepare_msgs.get(n, [])) >= 2 * F + 1:
                msg_list = BFT2F_MESSAGE_LIST(msgs=[pp_msg] + self.prepare_msgs[n])
                P.append(msg_list)

        vc_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.VIEW_CHANGE,
                               node_id=self.node_id,
                               view=self.view + 1,
                               version=self.V[self.node_id],
                               P=P,
                               sig="")
        vc_msg.sig = self.sign(vc_msg.SerializeToString())
        self.send_multicast(vc_msg)
        # Retry view changes until one succeeds
        self.start_timer()
        self.lock.release()

    def startProtocol(self):
        """
        Called after protocol has started listening.
        """
        # Set the TTL>1 so multicast will cross router hops:
        self.transport.setTTL(5)
        # Join a specific multicast group:
        self.transport.joinGroup(MULTICAST_ADDR)

    def datagramReceived(self, datagram, address):
        self.lock.acquire()
        msg = BFT2F_MESSAGE()
        msg.ParseFromString(datagram)

        # signature verification
        if msg.msg_type == BFT2F_MESSAGE.REQUEST:
            self.client_addr[msg.client_id] = address
            signer = self.client_pubkeys[msg.client_id]
        else:
            signer = self.server_pubkeys[msg.node_id]
        signature = msg.sig
        msg.sig = ""
        if not self.verify(signer,signature,msg.SerializeToString()):
            self.printv("wrong signature : %d :"%msg.node_id, msg.msg_type)
            self.lock.release()
            return
        msg.sig = signature

        # Refuse normal-case requests during view changes
        if msg.msg_type == BFT2F_MESSAGE.REQUEST and self.state == NodeState.NORMAL:
            self.printv("Recieved a REQUEST")
            self.handle_request(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.PRE_PREPARE and self.state == NodeState.NORMAL:
            self.printv("Recieved a PRE_PREPARE")
            self.handle_pre_prepare(msg)
        elif msg.msg_type == BFT2F_MESSAGE.PREPARE and self.state == NodeState.NORMAL:
            self.printv("Recieved a PREPARE n: %d" % msg.n)
            self.handle_prepare(msg)
        elif msg.msg_type == BFT2F_MESSAGE.COMMIT and self.state == NodeState.NORMAL:
            self.printv("Recieved a COMMIT")
            self.handle_commit(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.VIEW_CHANGE:
            self.handle_view_change(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.NEW_VIEW:            
            self.printv("Recieved a NEW_VIEW")
            self.handle_new_view(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.FAST_FORWARD_REQUEST:
            self.printv("Recieved a FAST_FORWARD_REQUEST from %d" % msg.node_id)
            self.handle_fast_forward_req(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.FAST_FORWARD_REPLY:
            self.printv("Recieved a FAST_FORWARD_REPLY")
            self.handle_fast_forward_rep(msg, address)
        elif msg.msg_type == BFT2F_MESSAGE.CHECKPOINT:
            self.printv("Recieved a CHECKPOINT")
            self.handle_checkpoint(msg, address)
        self.lock.release()
        
    def handle_request(self, msg, address):
        #TODO check fork state 
        last_rep_entry = self.replay_cache.get(msg.client_id)
        if last_rep_entry is not None:
            if last_rep_entry.req.ts > msg.ts:
                self.printv('ignored: ts too small %d' % msg.ts)
                self.printv(msg)
                return
            elif last_rep_entry.req.ts == msg.ts:
                self.printv('REPLAY! ts %d' % msg.ts)
                self.printv(msg)
                self.send_msg(last_rep_entry.rep, address)
                return
            elif last_rep_entry.rep.version.hcd != msg.version.hcd:
                self.printv('ignored incorrect HCD version')
                self.printv('replay cache v' + str(last_rep_entry.rep.version))
                self.printv('msg' + str(msg.version))
                return

        if self.node_id == self.primary(self.view):
            self.printv("Handling request")
            pp_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PRE_PREPARE,
                                            node_id=self.node_id,
                                            view=self.view,
                                            n=self.highest_accepted_n + 1,
                                            req_D=self.make_digest(msg.SerializeToString()),
                                            sig="")
            pp_msg.sig = self.sign(pp_msg.SerializeToString())
            self.send_multicast(pp_msg)

            # The primary updates its state before sending out any other
            # pre_prepare message
            self.handle_pre_prepare_helper(pp_msg)

        self.request_msgs[self.make_digest(msg.SerializeToString())] = msg

        # TODO: Does it make sense for the primary to set a view-change
        # timer for the primary, as we do here?
        self.start_timer()

    def handle_pre_prepare_helper(self, msg):
        """
        Bind the pre-prepare message to its sequence number,
        and multicast prepare messages.
        """
        self.pre_prepare_msgs[msg.n] = msg
        self.highest_accepted_n = msg.n

        p_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PREPARE,
                              node_id=self.node_id,
                              view=self.V[self.node_id].view,
                              n=msg.n,
                              req_D=msg.req_D,
                              sig="")
        p_msg.sig = self.sign(p_msg.SerializeToString())
        self.send_multicast(p_msg)

    def handle_pre_prepare(self, msg):
        """
        pre_prepare: <node-id, view, n, D(msg_n)>
        """
        # Reject the message if any of the following hold:
        # 1) This replica is the primary. It has already processed
        #    the pre-prepare message.
        # 2) This message is for a view different from our own.
        # 3) This message is not from the primary.
        # 4) This message's sequence number is too high
        # 5) This message is for a request that we haven't yet seen.
        #    TODO: The primary should retransmit pre-prepares to
        #          account for this. -A
        # 6) This replica has already accepted a different pre_prepare
        #    for this sequence number.
        if self.node_id == self.primary(self.view) or\
           self.view != msg.view or\
           msg.node_id != self.primary(self.view) or\
           not self.seqno_in_bounds(msg.n) or\
           msg.req_D not in self.request_msgs or\
           (self.pre_prepare_msgs.get(msg.n) and\
                self.pre_prepare_msgs.get(msg.n) != msg):
            self.printv('ignore pre_prepare')
            self.printv('highest %d' % self.highest_accepted_n)
            self.printv('self view %d msg view %d' % (self.view, msg.view))
            if msg.req_D not in self.request_msgs:
                self.printv('didn\'t receive request')
            if (self.pre_prepare_msgs.get(msg.n) and\
                self.pre_prepare_msgs.get(msg.n) != msg):
                self.printv('prepared a different message')
                self.printv(self.pre_prepare_msgs.get(msg.n))
            self.printv(msg)
            return;

        self.handle_pre_prepare_helper(msg)

    def handle_prepare(self, msg):        
        """
        prepare: <node-id, view, n, D(msg_n)>
        """
        # Only process this prepare message if
        #   1) its sequence number is in bounds;
        #   2) we haven't seen it before; and
        #   3) its for our view
        if (not self.seqno_in_bounds(msg.n)) or\
            msg in self.prepare_msgs.setdefault(msg.n, []) or\
            self.view != msg.view:
            return
        self.prepare_msgs[msg.n].append(msg)

        # Only commit this message if all lower sequence numbers
        # have been committed.
        if msg.n != self.highest_committed_n + 1:
            return

        # Enter the commit phase for all prepared pending requests
        # in ascending sequence number order
        pending_n = [n for n in self.pre_prepare_msgs.keys()\
                           if n > self.highest_committed_n + 1]
        pending_n = [msg.n] + sorted(pending_n)
        for n in pending_n:
            if len(self.prepare_msgs.setdefault(n, [])) == 2 * F + 1:
                req_D = self.prepare_msgs[n][0]
                r_msg = self.request_msgs[msg.req_D]
                new_hcd = self.make_digest(self.make_digest(r_msg.SerializeToString()) +\
                                               self.V[self.node_id].hcd)
                self.T[n] = HistoryEntry(hcd=new_hcd, matching_versions=[])

                new_version = BFT2F_VERSION(node_id=self.node_id,
                                            view=self.V[self.node_id].view,
                                            n=n,
                                            hcd=self.T[n].hcd,
                                            sig="")
                new_version.sig = self.sign(new_version.SerializeToString())            
                self.V[self.node_id] = new_version

                c_msg = BFT2F_MESSAGE(node_id=self.node_id,
                                      msg_type=BFT2F_MESSAGE.COMMIT,
                                      version=new_version,
                                      sig="")
                c_msg.sig = self.sign(c_msg.SerializeToString())
                self.send_multicast(c_msg)

    def handle_commit(self, msg, address):
        """
        commit: <version-vector-entry>
        """
        # We already updated our own version vector when we prepared
        # this request
        if self.node_id == msg.node_id:
            return

        if not self.seqno_in_bounds(msg.version.n):
            self.printv('OOB commit')
            return

        # Commit the operation if we have 2F + 1 matching versions for
        # it, including our own.
        self.V[msg.node_id] = msg.version
        matching_versions = [v for v in self.V\
                                if self.versions_match(v, msg.version)]
        if self.versions_match(self.V[self.node_id], msg.version) and\
                len(matching_versions) == 2 * F + 1:
            # Update the history entry to include the commit proof
            self.T[msg.version.n] = HistoryEntry(hcd=self.T[msg.version.n].hcd,
                                         matching_versions=matching_versions)
            self.highest_committed_n = msg.version.n
            
            # execute the operation and cancel the timer -- the request is
            # complete
            #
            # NB: It's possible that there exists one or other requests that
            # are waiting. We do not initialize a timer for these requests;
            # the next client request we receive will do so for us.
            r_msg = self.request_msgs[self.pre_prepare_msgs[msg.version.n].req_D]
            res = self.execute_op(r_msg.op)
            self.cancel_timer() 

            # respond to the client
            client_id = r_msg.client_id
            rp_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.REPLY,
                                   client_id=r_msg.client_id,
                                   node_id=self.node_id,
                                   ts=r_msg.ts,
                                   res=res,
                                   version=self.V[self.node_id],
                                   sig="")
            rp_msg.sig = self.sign(rp_msg.SerializeToString())
            self.replay_cache[r_msg.client_id] = CacheEntry(req=r_msg, rep=rp_msg)
            self.printv("replying to %s %s" % (client_id, PORT))
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
                raise NotImplementedError('Checkpoints not finished!')
        raise NotImplementedError('Checkpoints not finished!')

    def handle_view_change(self, msg, address):
        if self.primary(msg.view) == self.node_id:
            self.printv('Got view change!')
            if not self.valid_P(msg.P):
                self.printv('Invalid P!')
                return
            p_version = self.V[self.node_id]

            # Only process the view change message if we dominate it
            # and if it's valid
            if self.valid_view_change(msg):
                self.printv('Updating state!')
                self.try_new_view(msg)
            elif self.version_dominates_strictly(msg.version, p_version):
                self.printv('Fast forwarding!')
                self.request_fast_forward(address)
                self.pending_view_change_msgs[msg.node_id] = msg
            else:
                self.printv('ignoring!')
                return #ignore

    def request_fast_forward(self, address):
        ff_req = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.FAST_FORWARD_REQUEST,
                               node_id=self.node_id,
                               version=self.V[self.node_id],
                               sig="")
        ff_req.sig = self.sign(ff_req.SerializeToString())
        self.send_msg(ff_req, address)

    def valid_view_change(self, msg):
        """
        A view change message is valid if and only if
            1) the primary's version dominates it;
            2) the primary's version seqno appears in its own history, at the
               appropriate location; and
            3) the replica's version seqno appears in the primary's history, at
               the appropriate location.
        """
        p_version = self.V[self.node_id]
        return self.version_dominates(p_version, msg.version) and\
            p_version.n in self.T and self.T[p_version.n].hcd == p_version.hcd and\
            msg.version.n in self.T and self.T[msg.version.n].hcd == msg.version.hcd

    def try_new_view(self, msg):
        """
        Add the view-change message msg to the primary's bag of view change
        messages. If there are 2F+1 valid, non-conflicting view-change
        messages, then multicast a new-view message and update our view
        -- the view change is complete.
        """
        self.view_change_msgs.append(msg)
        unique_node_ids = [vc_msg.node_id for vc_msg in self.view_change_msgs]
        unique_node_ids = set(unique_node_ids)
        if len(unique_node_ids) < 2 * F + 1:
            return

        V, O = self.generate_V_and_O(self.view_change_msgs)
        if V is not None and O is not None:
            self.printv('Successfully generated V and O. Sending NEW VIEW')
            nv_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.NEW_VIEW,
                                   node_id=self.node_id,
                                   view=self.view + 1,
                                   version=self.V[self.node_id],
                                   V=V,
                                   O=O.values(),
                                   sig="")
            nv_msg.sig = self.sign(nv_msg.SerializeToString())
            self.send_multicast(nv_msg)

            # Update to the new view
            self.process_new_view(nv_msg)
            self.pending_view_change_msgs = {}
            self.view_change_msgs = []
        else:
            self.printv('Failed to make V and O.')

    def generate_V_and_O(self, view_msgs):
        """
        Attempt to generate a list of 2F+1 valid, non-conflicting messages
        and a dict of prepared-but-not-committed operations by taking the union
        of the view-change messages' P fields. Return a tuple (V, O) on success,
        (None, None) on failure.
        """
        V = []
        O = {}
        for vc_msg in view_msgs:
            valid_vc_msg = True
            for P_m in vc_msg.P:
                cur_pp_msg = P_em[0]                    
                new_pp_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.PRE_PREPARE,
                                           node_id=self.node_id,
                                           view=vc_msg.view,
                                           n=cur_pp_msg.n,
                                           req_D=cur_pp_msg.req_d,
                                           sig="")
                new_pp_msg.sig = self.sign(new_pp_msg.SerializeToString())
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
                    new_pp_msg.sig = self.sign(new_pp_msg.SerializeToString())
                    O[n] = new_pp_msg
            return (V, O)
        else:
            self.printv('Failed to make V: len %d' % len(V))
            return (None, None)

    def valid_P(self, P):
        """
        Return True iff P contains 2F+1 (pre)prepare messages,
        each from a unique replica.
        """
        for P_m in P:
            cur_pp_msg = P_em[0]
            unique_p_msgs = list(set(P_m[1:]))
            if len(unique_p_msgs) < 2 * F + 1:
                return False            
            for u_p_msg in unique_p_msg:
                signer = self.server_pubkeys[u_p_msg.node_id]
                signature = u_p_msg.sig
                u_p_msg.sig = ""
                if not self.verify(signer, signature, u_p_msg.SerializeToString()):
                    return False
                if not self.equiv_prepares(u_p_msg, cur_pp_msg):
                    return False
        return True
        
    def handle_new_view(self, msg, address):
        self.printv('Got a new view msg! %d' % self.node_id)

        # Only accept the new-view message if it comes from 
        # the primary of the view for which it's for
        if msg.node_id != self.primary(msg.view):
            return

        # It's possible that this replica did not time-out,
        # so update the state as a pre-caution
        self.state = NodeState.VIEW_CHANGE

        if not all(self.valid_P(vc_msg.P) for vc_msg in msg.V):
            return

        # Regenerate V and O to ensure that the primary
        # properly constructed them.
        V, O = self.generate_V_and_O(msg.V)
        if V == None or O == None:
            return
        if not self.valid_V(V):
            return
        if len(O) != len(msg.O):
            return
        for pp_msg in msg.O:
            if not equiv_prepares(O.get(pp_msg.n), pp_msg):
                return

        # If we're behind the primary, then we wait until we catch up to it
        # before changing views
        if self.version_dominates_strictly(msg.version, self.V[self.node_id]):
            self.printv('dominator ' + str(msg.version))
            self.printv('me ' + str(self.V[self.node_id]))
            self.pending_new_view_msg = msg
            self.request_fast_forward(address)
        else:
            self.process_new_view(msg)

    def valid_V(self, V):
        """
        Return True iff P contains 2F+1 view-change messages,
        each from a unique replica.
        """
        unique_node_ids = [vc_msg.node_id for vc_msg in V]
        unique_node_ids = set(unique_node_ids)
        if len(unique_node_ids) < 2 * F + 1:
            return False
        
        for vc_msg in V:
            signer = self.server_pubkeys[vc_msg.node_id]
            signature = vc_msg.sig
            vc_msg.sig = ""            
            if not self.verify(signer,signature,vc_msg.SerializeToString()):
                vc_msg.sig = signature
                return False
            vc_msg.sig = signature

        return True

    def process_new_view(self, msg):
        """
        Update state to advance to the new view, and handle all unseen
        pre_prepares in the set O.
        """
        self.printv('New View: me %d view %d' % (self.node_id, msg.view))
        self.cancel_timer()
        self.view = msg.view
        self.state=NodeState.NORMAL
        self.pending_new_view_msg = None

        sorted_pp_msgs = sorted(msg.O, key=lambda pp_msg: pp_msg.n)
        for pp_msg in sorted_pp_msgs:
            # we skip messages that have already committed,
            # since we assume that all replicas will fast-forward
            # to the primary
            if self.highest_committed_n >= pp_msg.n:
                continue
            self.handle_pre_prepare(pp_msg)
        
    def equiv_prepares(self, pp_msg_1, pp_msg_2):        
        """
        Return True iff two (pre)prepares match in all fields
        but the signature.
        """
        return pp_msg_1 and pp_msg2 and\
            pp_msg_1.n == pp_msg_2.n and\
            pp_msg_1.view == pp_msg_2.view and\
            pp_msg_1.req_D == pp_msg_2.req_D

    def handle_fast_forward_req(self, msg, address):
        req_proofs = []
        r_version = self.V[self.node_id]        
        # TODO Double check this logic -A
        if self.version_dominates(r_version, msg.version) and\
                r_version.n in self.T and self.T[msg.version.n].hcd == r_version.hcd and\
                msg.version.n in self.T and self.T[msg.version.n].hcd == msg.version.hcd:
            for i in range(msg.version.n + 1, r_version.n+ 1):
                r_msg = self.request_msgs[self.pre_prepare_msgs[i].req_D]
                req_proofs.append(BFT2F_REQUEST_PROOF(req=r_msg,
                                                      matching_versions=self.T[i].matching_versions))

        ff_rep_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.FAST_FORWARD_REPLY,
                                   node_id=self.node_id,
                                   req_proofs=req_proofs,
                                   sig="")
        ff_rep_msg.sig = self.sign(ff_rep_msg.SerializeToString())
        self.send_msg(ff_rep_msg, address)

    def handle_fast_forward_rep(self, msg, address):
        for rp in msg.req_proofs:
            if self.valid_req_proof(rp):
                # Update state
                self.T[self.node_id] = HistoryEntry(hcd=rp.matching_versions[0].hcd,
                                                    matching_versions=rp.matching_versions)
                self.V[self.node_id] = BFT2F_VERSION(node_id=self.node_id,
                                                     view=rp.matching_versions[0].view,
                                                     n=rp.matching_versions[0].n,
                                                     hcd=self.T[msg.n].hcd)
                self.view = rp.matching_versions[0].view
                self.highest_committed_n = rp.matching_versions[0].n
                if self.highest_committed_n > self.highest_accepted_n:
                    self.highest_accepted_n = self.highest_committed_n
                # Execute operation
                self.execute_op(rp.req.op)
            else:
                #break if invalid req_proof
                break

        if msg.node_id in self.pending_view_change_msgs:            
            self.handle_view_change(self.pending_view_change_msgs[msg.node_id], address)
        elif self.pending_new_view_msg and\
             msg.node_id == self.pending_new_view_msg.node_id:
            # TODO double check this logic -A
            self.process_new_view(self.pending_new_view_msg)

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
            if not self.verify(signer, signature, v.SerializeToString()):
                return False

            # Verify HCD
            new_hcd = self.make_digest(self.make_digest(req_proof.req.SerializeToString()) +\
                                           self.V[self.node_id].hcd)
            if new_hcd != new_v.hcd:
                return False

        return True

    # returns true iff v1 dominates v2
    def version_dominates(self, v1, v2):
        return v1.view >= v2.view and\
            ((v1.n == v2.n and v1.hcd == v2.hcd) or v1.n > v2.n)

    # returns true iff v1 dominates v2 strictly
    def version_dominates_strictly(self, v1, v2):
        return v1.view > v2.view or (v1.view == v2.view and v1.n > v2.n)

    def start_timer(self):
        if self.timer is None:
            self.timer = Timer(VIEW_TIMEOUT,self.change_view, args=[])
            self.timer.start()
            self.printv('START')

    def cancel_timer(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
            self.printv('CANCEL')

    def execute_op(self, op):
        #TODO tokens
        if op.type == SIGN_UP:
            if op.user_id in self.user_store:
                return BFT2f_OP_RES(type=BFT2f_OP_RES.USER_ID_EXISTS,
                                    op_type=op.type,
                                    user_id=op.user_id)
            self.user_store[op.user_id] = UserStoreEntry(user_pub_key=op.user_pub_key,
                                                         user_priv_key_enc=op.user_priv_key_enc)
            return BFT2f_OP_RES(type=BFT2f_OP_RES.SUCCESS,
                                op_type=op.type,
                                user_id=op.user_id,
                                user_pub_key=op.user_pub_key,
                                user_priv_key_enc=op.user_priv_key_enc)
        elif op.type == SIGN_IN:
            if op.user_id not in self.user_store:
                return BFT2f_OP_RES(type=BFT2f_OP_RES.USER_ID_NOT_FOUND,
                                    op_type=op.type,
                                    user_id=op.user_id,
                                    token=op.token)
            user_store_ent = self.user_store.get(op.user_id)
            sign_in_cert = BFT2f_SIGN_IN_CERT(
                node_pub_key=self.server_pubkeys[self.node_id]._key.exportKey(),
                sig=self.sign(op.token + user_store_ent.user_pub_key))
            self.printv("auth_str="+op.token + user_store_ent.user_pub_key)

            return BFT2f_OP_RES(type=BFT2f_OP_RES.SUCCESS,
                                op_type=op.type,
                                user_id=op.user_id,
                                user_pub_key=user_store_ent.user_pub_key,
                                user_priv_key_enc=user_store_ent.user_priv_key_enc,
                                token=op.token,
                                sign_in_cert=sign_in_cert)
        elif op.type == CHANGE_CRED:
            if op.user_id not in self.user_store:
                return BFT2f_OP_RES(type=BFT2f_OP_RES.USER_ID_NOT_FOUND,
                                    op_type=op.type,
                                    user_id=op.user_id)

            user_store_ent = self.user_store.get(op.user_id)
            signer = PKCS1_v1_5.new(RSA.importKey(user_store_ent.user_pub_key))

            if not self.verify(signer, op.sig, op.new_user_pub_key):
                return BFT2f_OP_RES(type=BFT2f_OP_RES.INVALID_CRED_CHANGE,
                                    op_type=op.type,
                                    user_id=op.user_id)
            # Update user_store entry
            self.user_store[op.user_id] = UserStoreEntry(user_pub_key=op.new_user_pub_key,
                                                         user_priv_key_enc=op.new_user_priv_key_enc)

            return BFT2f_OP_RES(type=BFT2f_OP_RES.SUCCESS,
                                op_type=op.type,
                                user_id=op.user_id,
                                user_pub_key=op.new_user_pub_key,
                                user_priv_key_enc=op.new_user_priv_key_enc)

    def make_checkpoint(self, n):
        hcd_n = self.T[n]
        self.pending_checkpoints[n] = Checkpoint(kv_store=self.kv_store,
                                                 hcd=hcd_n,
                                                 V=self.V,
                                                 replay_cache=self.replay_cache)
        ck_msg = BFT2F_MESSAGE(msg_type=BFT2F_MESSAGE.CHECKPOINT,
                              node_id=self.node_id,
                              n=n,
                              state_D=self.make_digest(str(self.kv_store) + hcd_n),
                              replay_cache_D=self.make_digest(str(self.replay_cache)),
                              sig="")
        ck_msg.sig = self.sign(ck_msg.SerializeToString())
        self.send_multicast(ck_msg)

    # TODO: low water mark, high water mark
    def seqno_in_bounds(self, n):
        return n <= self.highest_accepted_n + 10

    def versions_match(self, v1, v2):
        return (v1.view == v2.view) and (v1.n == v2.n) and (v1.hcd == v2.hcd)

    def versions_list_match(self, versions):        
        for v in verions:
            if not self.versions_match(v, versions[0]):
                return False
        return True

    def send_msg(self, msg, address):
        self.transport.write(msg.SerializeToString(), address)

    def send_multicast(self, msg):
        self.transport.write(msg.SerializeToString(), (MULTICAST_ADDR, PORT))

    def make_digest(self, data):
        digest = SHA.new(data)
        return b64encode(digest.digest())

    def verify(self, signer, signature, data):
        digest = SHA.new(data) 
        if signer.verify(digest, b64decode(signature)):
            return True
        return False

    def sign(self, data):
        digest = SHA.new(data)
        sign = self.private_key.sign(digest) 
        return b64encode(sign)

    def primary(self, view):
        return view % (3 * F + 1)

    def printv(self, text):
        if self.verbose:
            print text
            sys.stdout.flush()

def main():
    parser = ArgumentParser()
    parser.add_argument('--node_id', '-n',
                            type=long,
                            required=True)
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    reactor.listenMulticast(PORT, BFT2F_Node(args.node_id, args.verbose), listenMultiple=True)
    reactor.run()

if __name__ == '__main__':
	main()
