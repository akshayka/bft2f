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

BFT2F_PORT = 8005
USER_PORT = 9090

# F = 2

USER_ID = "user0"
USER_PW = "noseparecebien"
CLIENT_ADDR = "228.0.0.5"
PORT = 8000
BUFFER_SIZE = 1024
email_sender="jongho271828@gmail.com"
email_receiver="peaces1@gmail.com"
priv_key_orig_filename="./certs/user0_enc2.key"
pub_key_orig_filename="./certs/user0.pem"
priv_key_tmp_filename="/tmp/user0key_priv.pem"
pub_key_tmp_filename="/tmp/user0key_pub.pem"

parser = ArgumentParser()
parser.add_argument('--client_ip', '-cp',
                    type=str,
                    required=True)
parser.add_argument('--app_ip', '-ap',
                    type=str,
                    required=True)
args = parser.parse_args()
print "start user"


def verify_func(signer, signature, data):
    digest = SHA.new(data) 
    if signer.verify(digest, b64decode(signature)):
        return True
    return False

def sign_func(signer, data):
    digest = SHA.new(data)
    sign = signer.sign(digest) 
    return b64encode(sign)

def main():
    f1=open(priv_key_orig_filename,"r")
    f2=open(pub_key_orig_filename,"r")
    # sign up
    retry = True
    while(retry):
        print "trying"
        sys.stdout.flush()
        retry = False
        try:
            transport = TSocket.TSocket(args.client_ip, USER_PORT)
            transport.setTimeout(5000)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = Auth_Service.Client(protocol)
            transport.open()
            rmsg = client.sign_up(user_id=USER_ID, user_pub_key=f2.read(), user_priv_key_enc=f1.read())
            print rmsg
            transport.close()
        except:
            print "crashed"
            sys.stdout.flush()
            retry=True
            #transport.close()
    f1.close()
    f2.close()    

    print "connecting to SMTP :" + args.app_ip
    sys.stdout.flush()
    s = smtplib.SMTP(args.app_ip,2225)
    print "connected to SMTP :" + args.app_ip
    sys.stdout.flush()
    res = s.ehlo()
    print res
    sys.stdout.flush()
    res = s.docmd('auth cram-cert')
    print res
    sys.stdout.flush()
    token = b64decode(res[1])

    
    retry = True
    while(retry):
        print "trying"
        sys.stdout.flush()
        retry = False
        try:     
            transport = TSocket.TSocket(args.client_ip, USER_PORT)
            transport.setTimeout(5000)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = Auth_Service.Client(protocol)
            transport.open()
            rmsg = client.sign_in(user_id=USER_ID, token=token)
            transport.close()
        except:
            print "crashed"
            sys.stdout.flush()
            retry=True
            #transport.close()
    
    print rmsg
    sign_in_certs = [[cert.node_pub_key, cert.sig] for cert in rmsg.sign_in_certs]
    auth_str = b64encode(json.dumps({'id':USER_ID, 'pub_key':rmsg.user_pub_key,'signature':sign_in_certs}))
    print auth_str
    sys.stdout.flush()
    res=s.docmd(auth_str)
    if res[0] != 235:
        print res
        print "Auth failed"
    key = RSA.importKey(rmsg.user_priv_key_enc,USER_PW)
    f = open(priv_key_tmp_filename,'w')
    f.write(key.exportKey('PEM'))
    f.close()
    key = RSA.importKey(rmsg.user_pub_key)
    f = open(pub_key_tmp_filename,'w')
    f.write(key.publickey().exportKey('PEM'))
    f.close()
    s.starttls(priv_key_filename,pub_key_filename)
    res = s.ehlo()
    print res
    sys.stdout.flush()
    # msg = MIMEText("cs244b test")
    # msg['Subject'] = "cs244b test"
    # msg['From'] = email_sender
    # msg['To'] = email_receiver
    # s.sendmail(email_sender, [email_receiver], msg.as_string())
    s.quit()

    # print res
    # sys.stdout.flush()
    #get priv_key, pubkey, signature
    #JSON + base64

if __name__ == '__main__':
    main()

