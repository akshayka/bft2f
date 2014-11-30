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

USER_ID = "user0"
USER_PW = "noseparecebien"
CLIENT_ADDR = "228.0.0.5"
PORT = 8000
BUFFER_SIZE = 1024
email_sender="jongho271828@gmail.com"
email_receiver="peaces1@gmail.com"
priv_key_filename="/tmp/user0key_priv.pem"
pub_key_filename="/tmp/user0key_pub.pem"


def main():
    s = smtplib.SMTP('localhost',2225)
    s.ehlo()
    res=s.docmd('auth cram-cert')
    token = b64decode(res[1])
    #send request to a bft2f client
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket
    # sock.sendto(BFT2F_SIGN_REQ(user_id=USER_ID, token=token), (CLIENT_ADDR, PORT))
    # sock.bind(("0.0.0.0", PORT))
    #while True:
    # datagram, addr = sock.recvfrom(1024)
    # print datagram,addr
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((CLIENT_ADDR, PORT))
    sock.send(BFT2F_SIGN_REQ(user_id=USER_ID, token=token).SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    sock.close()

    #get priv_key, pubkey, signature
    #JSON + base64
    rmsg=BFT2F_SIGN_RES()
    rmsg.ParseFromString(datagram)
    auth_str = b64encode(json.dumps({'id':USER_ID, 'pub_key':rmsg.pub_key,'signature':rmsg.signature}))
    res=s.docmd(auth_str)
    if res[0] != 235:
        print "Auth failed"
    key = RSA.importKey(rmsg.priv_key_enc,USER_PW)
    f = open(priv_key_filename,'w')
    f.write(key.exportKey('PEM'))
    f.close()
    key = RSA.importKey(rmsg.pub_key)
    f = open(pub_key_filename,'w')
    f.write(key.publickey().exportKey('PEM'))
    f.close()
    s.starttls(priv_key_filename,pub_key_filename)
    msg = MIMEText("cs244b test")
    msg['Subject'] = "cs244b test"
    msg['From'] = email_sender
    msg['To'] = email_receiver
    s.sendmail(email_sender, [email_receiver], msg.as_string())
    s.quit()

if __name__ == '__main__':
	main()
