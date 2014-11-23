#!/usr/bin/python

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

from signal import SIGINT
import sys
import os
import math

parser = ArgumentParser(description="BFT2F tests")
parser.add_argument('--bw-host', '-B',
                    type=float,
                    help="Bandwidth of host links (Mb/s)",
                    default=1000)

parser.add_argument('--bw-net', '-b',
                    type=float,
                    help="Bandwidth of bottleneck (network) link (Mb/s)",
                    required=True)

parser.add_argument('--delay',
                    type=float,
                    help="Link propagation delay (ms)",
                    required=True)

parser.add_argument('--dir', '-d',
                    help="Directory to store outputs",
                    required=True)

parser.add_argument('--time', '-t',
                    help="Duration (sec) to run the experiment",
                    type=int,
                    default=10)

parser.add_argument('--maxq',
                    type=int,
                    help="Max buffer size of network interface in packets",
                    default=100)

parser.add_argument('--cong',
                    help="Congestion control algorithm to use",
                    default="reno")

# Expt parameters
args = parser.parse_args()

class Bft2fTopo(Topo):

    def __init__(self, n=2):
        super(Bft2fTopo, self).__init__()

        # TODO: create two hosts
        h1=self.addHost('h1')
        h2=self.addHost('h2')

        # Here I have created a switch.  If you change its name, its
        # interface names will change from s0-eth1 to newname-eth1.
        switch=self.addSwitch('s0')

        # TODO: Add links with appropriate characteristics
        h1Linkopts = dict(bw=args.bw_host, delay='%fms'%args.delay, loss=0, max_queue_size=args.maxq, use_htb=True)
        h2Linkopts = dict(bw=args.bw_net,  delay='%fms'%args.delay, loss=0, max_queue_size=args.maxq, use_htb=True)
        # alternately: linkopts = {'bw':10, 'delay':'5ms', 'loss':10,
        # max_queue_size=1000, 'use_htb':True}
        self.addLink(h1,switch,**h1Linkopts)
        self.addLink(h2,switch,**h2Linkopts)
        return

# Simple wrappers around monitoring utilities.  You are welcome to
# contribute neatly written (using classes) monitoring scripts for
# Mininet!

def multicast_test(net,seconds=6):
    h1 = net.getNodeByName('h1')
    h2 = net.getNodeByName('h2')
    h1.cmd("route add -net default dev h1-eth0")
    h2.cmd("route add -net default dev h2-eth0")
    popens = {}
    #for h in net.hosts:
    #    popens[ h ] = h.popen('ping', server.IP() )
    print "Monitoring output for", seconds, "seconds"
    popens[h1]=h1.popen("python MulticastServer.py")
    sleep(1)
    popens[h2]=h2.popen("python MulticastClient.py")
    endTime = time() + seconds
    for h, line in pmonitor( popens, timeoutms=500 ):
        if h:
           print '%s: %s' % ( h.name, line ),
        if time() >= endTime:
           for p in popens.values():
              p.send_signal( SIGINT )

def bft2f():
    if not os.path.exists(args.dir):
        os.makedirs(args.dir)
    topo = Bft2fTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    # This dumps the topology and how nodes are interconnected through
    # links.
    dumpNodeConnections(net.hosts)
    # This performs a basic all pairs ping test.
    net.pingAll()
    multicast_test(net)
    #CLI(net)
    net.stop()

if __name__ == "__main__":
    bft2f()

