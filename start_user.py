import sys
from bft2f_pb2 import *

import smtplib
from email.mime.text import MIMEText
import json
import socket

from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA 
from base64 import b64encode, b64decode

USER_ID = "test"
USER_PW = "noseparecebien"
CLIENT_ADDR = "228.0.0.5"
PORT = 8005
F = 2


def main():
    s = smtplib.SMTP('localhost',2225)
    s.ehlo()
    res=s.docmd('auth cram-cert')
    token = res[1]
    #send request to a bft2f client
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket
    sock.sendto(BFT2F_SIGN_REQ(user_id=USER_ID, token=token), (CLIENT_ADDR, PORT))
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
	main()
