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

from subprocess import Popen, PIPE
from time import sleep, time

NUMBER_NODES = 7


class BftTopo(Topo):
    def __init__(self, n=2):
        super(BftTopo, self).__init__()
        s0 = self.addSwitch('s0')

        # create hosts
        hosts = []
        for i in range(0, NUMBER_NODES):
            hosts.append(self.addHost('h%d' % (i)))        
        for h in hosts:
            self.addLink(h, s0)

        client = self.addHost('client')
        self.addLink(client, s0)

        return


def start_nodes(net):
  hosts = []
  rep_ips = {}
  for i in range(0, NUMBER_NODES):
      h = net.getNodeByName('h%d'%(i))
      rep_ips[i] = h.IP()
      hosts.append(h)
  for i in range(0, NUMBER_NODES):
      h = hosts[i]
      print 'python start_node.py --name=%d --rep_addr=%s >> node.out' % \
			(i, str(rep_ips[i]))
      p = h.popen('python start_node.py --name=%d --rep_addr=%s >> node.out' %
			     (i, str(rep_ips[i])), shell=True)
      

def start_client(net):
    client = net.getNodeByName('client')    
    p = client.popen('python start_client.py --dest_addr=10.255.255.255 >> node.out',
                     shell=True)


def main():
	# Clear the output file
    Popen('rm node.out', shell=True).wait()
    topo = BftTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    # This dumps the topology and how nodes are interconnected through
    # links.
    dumpNodeConnections(net.hosts)
    start_nodes(net)
    CLI(net)
    net.stop()
    # Ensure that all processes created with Mininet are killed.
    Popen('pgrep -f webserver.py | xargs kill -9', shell=True).wait()


if __name__ == '__main__':
    main()
