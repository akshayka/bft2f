#!/usr/bin/python
import sys
import os
from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from mininet.util import pmonitor

from subprocess import Popen, PIPE
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser

import signal

NUMBER_NODES = 7
NUMBER_CLIENTS = 1
NUMBER_USERS = 1
RUN_DURATION = 35
popens = {}

LINK_BW=10
LINK_DELAY='10ms'
LINK_LOSS=10
ETC_HOSTS_FILE_NAME="bft2f_etc_hosts"
DEBUG_OUTPUT_FILE='bft2f.debug'

class BftTopo(Topo):
    def __init__(self, n=2):
        super(BftTopo, self).__init__()
        s0 = self.addSwitch('s0')
        # create hosts
        for i in xrange(0, NUMBER_NODES):
            self.addLink(self.addHost('h%d' % (i)), s0, bw=LINK_BW, delay=LINK_DELAY)
        for i in xrange(0, NUMBER_CLIENTS):
            self.addLink(self.addHost('c%d' % (i)), s0, bw=LINK_BW, delay=LINK_DELAY)
        for i in xrange(0, NUMBER_USERS):
            self.addLink(self.addHost('u%d' % (i)), s0, bw=LINK_BW, delay=LINK_DELAY)
        self.addLink(self.addHost('app'), s0, bw=LINK_BW, delay=LINK_DELAY)
        return

def start_nodes(net, verbose):
    for i in range(0, NUMBER_NODES):
        h = net.getNodeByName('h%d'%(i))
        h.cmd("route add -net default dev h%d-eth0" % (i))
        if verbose:
            cmd = 'python start_node.py --node_id=%d -v >>%s 2>&1' % (i, DEBUG_OUTPUT_FILE)
        else:
            cmd = 'python start_node.py --node_id=%d >>%s 2>&1' % (i, DEBUG_OUTPUT_FILE)
        popens[h] = h.popen(cmd, shell=True, preexec_fn=os.setsid)
      
def start_client(net):
    for i in xrange(0, NUMBER_CLIENTS):
        client = net.getNodeByName('c%d' % (i))
        client.cmd("route add -net default dev c%d-eth0" % (i))
        popens[client] = client.popen('python start_client.py --client_id=%d' % (i),
                                      shell=True, preexec_fn=os.setsid)

def start_user(net):
    app = net.getNodeByName('app')
    for i in xrange(0, NUMBER_USERS):
        user = net.getNodeByName('u%d'%(i))
        client = net.getNodeByName('c%d' % (i))
        user.cmd("route add -net default dev u%d-eth0" % (i))
        #popens[user] = client.popen('python start_user.py --user_id=%d --client_ip=%s --app_ip=%s  >>%s 2>&1' % (i, client.IP(), app.IP(), DEBUG_OUTPUT_FILE), shell=True, preexec_fn=os.setsid)

def start_app(net):
    app = net.getNodeByName('app')
    app.cmd("route add -net default dev app-eth0")
    popens[app] = app.popen('node haraka.js >>%s 2>&1' % (DEBUG_OUTPUT_FILE),
                                  shell=True, preexec_fn=os.setsid, cwd='./Haraka')
    
def create_etc_hosts(net):
    with open(ETC_HOSTS_FILE_NAME, "w+") as f:
        for h in net.values():
            f.write("%s\t%s\n" % (h.name, h.IP()))
        
def main():
    parser = ArgumentParser()
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    topo = BftTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    create_etc_hosts(net)
    # This dumps the topology and how nodes are interconnected through
    # links.
    dumpNodeConnections(net.hosts)
    start_app(net)
    start_nodes(net, args.verbose)
    start_client(net)

    #CLI(net)

    sleep(5)
    start_user(net)
    CLI(net)
    endTime = time() + RUN_DURATION

    for p in popens.values():
       os.killpg(p.pid, signal.SIGTERM)
    net.stop()

if __name__ == '__main__':
    main()
