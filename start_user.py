#!/usr/bin/python
import os
import sys, glob
from bft2f_pb2 import *
sys.path.append('gen-py')
from user_base import get_client, get_host_ip
from argparse import ArgumentParser
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA 
from smtplib import SMTP
import socket
import json
from base64 import b64encode, b64decode

BUFFER_SIZE = 10000

def my_sign(private_key, data):
    digest = SHA.new(data)
    res = private_key.sign(digest) 
    return b64encode(res)



import sys, glob
from bft2f_pb2 import *
sys.path.append('gen-py')
from user_base import get_client
from argparse import ArgumentParser
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5

from multiprocessing import Pool
import os
import sys, glob
from bft2f_pb2 import *
sys.path.append('gen-py')
from auth_service import Auth_Service
from auth_service.ttypes import *

import time
from time import sleep, time
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

CLIENT_ADDR = "228.0.0.5"
PORT = 8000
BUFFER_SIZE = 1024
# email_sender="jongho271828@gmail.com"
# email_receiver="peaces1@gmail.com"

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
    res = s.ehlo()
    print res
    sys.stdout.flush()   
    key = RSA.importKey(rmsg.user_priv_key_enc,USER_PW)
    f = open(priv_key_tmp_filename,'w')
    f.write(key.exportKey('PEM'))
    f.close()
    # key = RSA.importKey(rmsg.user_pub_key)
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



def sign_up(user_id, passphrase, client_id):
    client, t = get_client(client_id)
    key = RSA.generate(2048)
    signer1 = PKCS1_v1_5.new(key)
    pub_key = key.publickey().exportKey('PEM')
    priv_key_enc = key.exportKey('PEM', passphrase=passphrase)
    rmsg = client.sign_up(user_id=user_id, user_pub_key=pub_key, user_priv_key_enc=priv_key_enc)
    print rmsg
    t.close()

def sign_in(user_id, passphrase, client_id):
    app_ip = get_host_ip("app")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((app_ip,2225))
    data = s.recv(BUFFER_SIZE)
    data = s.recv(BUFFER_SIZE)
    s.send("auth cram-cert\n")
    data = s.recv(BUFFER_SIZE)
    token = b64decode(data.split(" ")[1])

    client, t = get_client(client_id)
    rmsg = client.sign_in(user_id=user_id, token=token)
    t.close()
    print str(rmsg)[:80],"..."

    sign_in_certs = [[cert.node_pub_key, cert.sig] for cert in rmsg.sign_in_certs]
    try:
        priv_key = PKCS1_v1_5.new(RSA.importKey(rmsg.user_priv_key_enc,passphrase))
    except:
        print("Wrong password")
        exit()
    sign_in_certs.append([rmsg.user_pub_key, my_sign(priv_key, token+rmsg.user_pub_key)])
    auth_str = b64encode(json.dumps({'id':user_id, 'pub_key':rmsg.user_pub_key,'signature':sign_in_certs}))

    s.send(auth_str+"\n")
    data = s.recv(BUFFER_SIZE)
    print data

    s.close()

def sign_in(u_and_p):
    user_id = u_and_p[0]
    passphrase = u_and_p[1]
    client_id = u_and_p[2]
    os.system("./sign_in -u %s -p %s -cid '%s'" % (user_id, passphrase, "c%d" %(client_id)))
    return

def latency_test():

    user_ids = []
    passphrases = []
    for i in range(0, 20):
        user_id = "user%d%d" % (i, args.user_id)
        passphrase = "pass%d" %(i)
        user_ids.append(user_id)
        passphrases.append(passphrase)
        os.system("./sign_up -u %s -p %s -cid '%s'" % (user_id, passphrase, "c%d" %(args.user_id)))

        #sign_up("user%d%d" % (i, args.user_id), "pass%d" %(i), "c0")


    t0  = time()
    #print zip(user_ids, passphrases)
    
    #for user_id, passphrase, client_id in zip(user_ids, passphrases, [0] * 50):
    #    sign_in((user_id, passphrase, client_id))

    p = Pool(20)
    
    p.map(sign_in, zip(user_ids * 10, passphrases * 10, [0] * 200))
    p.close()
    p.join()

    print "Latency = %d" % (time() - t0)




        
if __name__ == '__main__':
    latency_test()

