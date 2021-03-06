import sys, glob
from bft2f_pb2 import *
sys.path.append('gen-py')
from auth_service import Auth_Service
from auth_service.ttypes import *

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

USER_PORT = 9090
ETC_HOSTS_FILE_NAME="bft2f_etc_hosts"

def get_host_ip(host_name):
    with open(ETC_HOSTS_FILE_NAME, "r+") as f:
        for l in f.readlines():
            name, ip = l.split("\t")
            if host_name == name:
                return ip


def get_client(client_id='c0'):
    client_ip = get_host_ip(client_id)
    transport = TSocket.TSocket(client_ip, USER_PORT)
    transport.setTimeout(20000)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    client = Auth_Service.Client(protocol)
    transport.open()

    return client, transport


