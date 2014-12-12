#!/usr/bin/python
import os, sys, glob
sys.path.append('gen-py')
from bft2f_pb2 import *
from user_base import get_client, get_host_ip
from argparse import ArgumentParser
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA 
from base64 import b64encode, b64decode
import socket
import json
import time
import smtplib
from email.mime.text import MIMEText

from multiprocessing import Pool
from auth_service import Auth_Service
from auth_service.ttypes import *

from twisted.internet import protocol, defer, endpoints, task
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

CLIENT_ADDR = "228.0.0.5"
BUFFER_SIZE = 2048
USER_PORT = 9090

parser = ArgumentParser()
parser.add_argument('--client_ip', '-cp',
                    type=str,
                    required=False)
parser.add_argument('--app_ip', '-ap',
                    type=str,
                    required=False)
parser.add_argument('--user_id', '-n',
                    type=long,
                    required=True)
args = parser.parse_args()

#init constants
USER_ID = "user%d"%(args.user_id)
USER_PW = "noseparecebien"
priv_key_orig_filename="./certs/user%d.key"%(args.user_id)
pub_key_orig_filename="./certs/user%d.crt"%(args.user_id)
priv_key_tmp_filename="/tmp/user%dkey_priv.key"%(args.user_id)
pub_key_tmp_filename="/tmp/user%dkey_pub.crt"%(args.user_id)

print "start user"

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
            transport.setTimeout(10000000)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = Auth_Service.Client(protocol)
            transport.open()
            my_time=time.time()
            rmsg = client.sign_up(user_id=USER_ID, user_pub_key=f2.read(), user_priv_key_enc=f1.read())
            print "Sign up latency : "+str(time.time()-my_time)
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
            my_time=time.time()
            rmsg = client.sign_in(user_id=USER_ID, token=token)
            print "Sign in latency : "+str(time.time()-my_time)
            transport.close()
        except:
            print "crashed"
            sys.stdout.flush()
            retry=True
    
    print rmsg
    sign_in_certs = [[cert.node_pub_key, cert.sig] for cert in rmsg.sign_in_certs]
    auth_str = b64encode(json.dumps({'id':USER_ID, 'pub_key':rmsg.user_pub_key,'signature':sign_in_certs}))
    print auth_str
    sys.stdout.flush()
    res=s.docmd(auth_str)
    if res[0] != 235:
        print res
        print "Auth failed"
    res = s.ehlo()
    print res
    sys.stdout.flush()   
    key = RSA.importKey(rmsg.user_priv_key_enc,USER_PW)
    f = open(priv_key_tmp_filename,'w')
    f.write(key.exportKey('PEM'))
    f.close()
    key = RSA.importKey(rmsg.user_pub_key)
    f = open(pub_key_tmp_filename,'w')
    f.write(rmsg.user_pub_key)
    f.close()
    s.starttls(priv_key_tmp_filename,pub_key_tmp_filename)
    res = s.ehlo()
    print res
    sys.stdout.flush()
    # msg = MIMEText("cs244b test")
    # msg['Subject'] = "cs244b test"
    # msg['From'] = email_sender
    # msg['To'] = email_receiver
    # s.sendmail(email_sender, [email_receiver], msg.as_string())
    s.quit()

def latency_test():
    user_ids = []
    passphrases = []
    #set up - generate login credentials
    for i in range(0, 20):
        user_id = "user%d%d" % (i, args.user_id)
        passphrase = "pass%d" %(i)
        user_ids.append(user_id)
        passphrases.append(passphrase)
        os.system("./sign_up -u %s -p %s -cid '%s'" % (user_id, passphrase, "c%d" %(args.user_id)))

    #start measuring
    sign_in = lambda id_and_pass: os.system("./sign_in -u %s -p %s -cid '%s'" % 
        (id_and_pass[0], id_and_pass[1], "c%d" %(id_and_pass[2])))
    p = Pool(20)
    t0 = time.time()
    p.map(sign_in, zip(user_ids * 10, passphrases * 10, [0] * 200))
    t1 = time.time()
    p.close()
    p.join()

    print "Latency = %d" % (t1 - t0)

        
if __name__ == '__main__':
    latency_test()

