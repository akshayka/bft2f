import sys, glob
from bft2f_pb2 import *
sys.path.append('gen-py')
from auth_service import Auth_Service
from auth_service.ttypes import *

import smtplib
from email.mime.text import MIMEText
import json
import socket
from argparse import ArgumentParser

from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA 
from base64 import b64encode, b64decode
from twisted.internet import protocol, defer, endpoints, task


from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol


USER_ID = "test"
USER_PW = "noseparecebien"
CLIENT_ADDR = "228.0.0.5"
BFT2F_PORT = 8005
USER_PORT = 9090

F = 2

parser = ArgumentParser()
parser.add_argument('--client_ip', '-cp',
                    type=str,
                    required=True)
args = parser.parse_args()
print "start user"


def sign_in():
    s = smtplib.SMTP('localhost',2225)
    s.ehlo()
    res=s.docmd('auth cram-cert')
    token = res[1]
    #send request to a bft2f client
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket
    sock.sendto(BFT2F_SIGN_REQ(user_id=USER_ID, token=token), (args.client_ip, PORT))
    sock.bind(("0.0.0.0", PORT))
    #get priv_key, pubkey, signature
    #while True:
    datagram, addr = sock.recvfrom(1024)
    print datagram,addr
    #JSON + base64
    rmsg=BFT2F_SIGN_RES()
    rmsg.ParseFromString(datagram)
    auth_str = b64encode(json.dumps({'id':USER_ID, 'pub_key':'','signature':''}))
    res=s.docmd(auth_str)
    if res[0] != 235:
        print "Auth failed"
    s.starttls(rmsg.priv_key_enc,rmsg.pub_key)
    msg = MIMEText("cs244b test")
    msg['Subject'] = "cs244b test"
    msg['From'] = me
    msg['To'] = you
    s.sendmail(me, [you], msg.as_string())
    s.quit()

if __name__ == '__main__':
    transport = TSocket.TSocket(args.client_ip, USER_PORT)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    client = Auth_Service.Client(protocol)
    transport.open()

    # Example sign up and sign in 
    res = client.sign_up(user_id="user_id", user_pub_key="user_pub_key", user_priv_key_enc="user_priv_key_enc")    
    print res
    sys.stdout.flush()
        
    res = client.sign_in(user_id="user_id", token="token")
    print res
    sys.stdout.flush()

