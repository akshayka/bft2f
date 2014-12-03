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
RUN_DURATION = 25
popens = {}


class BftTopo(Topo):
    def __init__(self, n=2):
        super(BftTopo, self).__init__()
        s0 = self.addSwitch('s0')

        # create hosts
        hosts = []
        for i in range(0, NUMBER_NODES):
            h = self.addHost('h%d' % (i))
            hosts.append(h)

        for h in hosts:
            self.addLink(h, s0)

        client = self.addHost('client')
        self.addLink(client, s0)
        self.addLink(self.addHost('app'), s0)
        user = self.addHost('user')
        self.addLink(user, s0)

        return


def start_nodes(net, verbose):
    for i in range(0, NUMBER_NODES):
        h = net.getNodeByName('h%d'%(i))
        h.cmd("route add -net default dev h%d-eth0" % (i))
        if verbose:
            cmd = 'python start_node.py --node_id=%d -v 2>&1' % i
        else:
            cmd = 'python start_node.py --node_id=%d 2>&1' % i
        popens[h] = h.popen(cmd, shell=True, preexec_fn=os.setsid)
      
def start_client(net):
    client = net.getNodeByName('client')
    client.cmd("route add -net default dev client-eth0")
    popens[client] = client.popen('python start_client.py --client_id=%d 2>&1' % (0),
                                  shell=True, preexec_fn=os.setsid)

def start_user(net):
    user = net.getNodeByName('user')
    client = net.getNodeByName('client')
    app = net.getNodeByName('app')
    user.cmd("route add -net default dev user-eth0")
    popens[user] = client.popen('python start_user.py --client_ip=%s --app_ip=%s 2>&1' % (client.IP(),app.IP()),
                                  shell=True, preexec_fn=os.setsid)

def start_app(net):
    app = net.getNodeByName('app')
    app.cmd("route add -net default dev app-eth0")
    popens[app] = app.popen('node haraka.js 2>&1',
                                  shell=True, preexec_fn=os.setsid, cwd='./Haraka')
    
def main():
    parser = ArgumentParser()
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    topo = BftTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    # This dumps the topology and how nodes are interconnected through
    # links.
    dumpNodeConnections(net.hosts)
    start_app(net)
    start_nodes(net, args.verbose)
    start_client(net)

    #CLI(net)

    sleep(5)
    start_user(net)
    #CLI(net)
    endTime = time() + RUN_DURATION
    num_processes = len(popens)
    for h, line in pmonitor(popens, timeoutms=500):
        if h:
            print '%s: %s' % ( h.name, line ),
        if time() >= endTime:
            break
    for p in popens.values():
        os.killpg(p.pid, signal.SIGTERM)
    net.stop()

if __name__ == '__main__':
    main()
