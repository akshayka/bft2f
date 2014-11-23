
#!/usr/bin/python

"CS244 Spring 2013 Assignment 1: Bufferbloat"


import sys
import os
import math
import numpy



from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

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


class BBTopo(Topo):
    "Simple topology for bufferbloat experiment."

    def __init__(self, n=2):
        super(BBTopo, self).__init__()

        s0 = self.addSwitch('s0')

        # create hosts
        hosts = []
        for i in range(0, NUMBER_NODES):
            hosts.append(self.addHost("h%d" % (i)))        
        for h in hosts:
            self.addLink(h, s0)

        client = self.addHost("client")
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
      p = h.popen('python start_node.py --name=%d --rep-addrs="%s" >> node.out' %(i, str(rep_ips)),
                  shell=True)
      #print p.communicate()
      print 'python start_node.py --name=%d --rep-addrs="%s" >> node.out' %(i, str(rep_ips))
      
def start_client(net):
    client = net.getNodeByName('client')    
    p = client.popen('python start_client.py --dest-addr=10.255.255.255 >> node.out',
                     shell=True)


def bft2f_topo():
    topo = BBTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    # This dumps the topology and how nodes are interconnected through
    # links.
    dumpNodeConnections(net.hosts)
    start_nodes(net)
    #sleep(2)
    #start_client(net)
    CLI(net)
    net.stop()
    # Ensure that all processes you create within Mininet are killed.
    # Sometimes they require manual killing.
    Popen("pgrep -f webserver.py | xargs kill -9", shell=True).wait()
    return

if __name__ == "__main__":
    bft2f_topo()
