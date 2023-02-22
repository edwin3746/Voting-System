import socket
import time
import os
import ssl
from hashlib import sha256

from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes, random
from server import server_address as server_address

## Pip install pycryptodomex

port = number.getRandomRange(1, 65536)
currentPath = os.getcwd()
auth1_address = ('127.0.0.2',port)

def generate_r(q):
    r = number.getRandomRange(2, q-2)
    return r

def sendCommitment(commitmentInfo,server):
    count = 0
    server.connect(server_address)

    while True:
        if server.recv(1024).decode("utf-8") == "Connection is secure":
            server.sendall(commitmentInfo)
        if server.recv(1024).decode("utf-8") == "Valid":
            server.close()
            break
        count += 1
        if count == 10:
            raise Exception()

def retrievePublicKeys(receivePubKeyInfo):
    count = 0
    receivePubKeyInfo.connect(server_address)
    pubKeyInfo = ""
    p = ""
    q = ""
    g = ""
    wait = "."

    while not pubKeyInfo or not p or not q or not g:
        receivePubKeyInfo.sendall(b'Retrieve public key parameters')
        pubKeyInfo = receivePubKeyInfo.recv(8192*10).decode("utf-8")
        p = int(pubKeyInfo.split("||")[0])
        q = int(pubKeyInfo.split("||")[1])
        g = int(pubKeyInfo.split("||")[2])
        count += 1
        if count == 10:
            raise Exception()
    if p and q and g:
        receivePubKeyInfo.sendall(b"Received Q!")

    while True:
        if receivePubKeyInfo.recv(1024).decode("utf-8") == "Partial Private Key Generated Complete!":
            time.sleep(3)
            receivePubKeyInfo.close()
            break

    ## Generate part of private key here (g^x mod p)
    partialx = number.getRandomRange(2,int(q)-2)
    partialPublicKey = pow(g, partialx, p)

    ## Commitment
    r = generate_r(q)
    secret = (pow(g,partialPublicKey,p) * pow(partialPublicKey, r, p)) % p
    return secret,partialPublicKey,r

# partial decrypt function
def partialDecrypt(a, privateKey, p):
    return pow(a, p-1-privateKey, p)

# creating the Schnorr signature
def schnorrSignature(p, q, g, privateKey, message):
    r = random.randint(1, q - 1)
    x = pow(g, r, p)
    e = hashThis(x, message) % p
    s = pow((r - (privateKey * e)), 1, p - 1)
    return e, s

# sample hash function
def hashThis(r, message):
    hash=sha256();
    hash.update(str(r).encode());
    hash.update(message.encode());
    return int(hash.hexdigest(),16)

def startSocket():
    auth1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    auth1 = ssl.wrap_socket(auth1, keyfile=currentPath+"\key.pem", certfile=currentPath+"\certificate.pem")

    auth1.bind(auth1_address)
    return auth1

def main():
    auth1 = startSocket()
    secret = ""
    partialPublicKey = ""
    r = ""
    count = 0

    # this message is to determine which server/authenticator sent the Schnorr signature
    message = "auth1"
    messageInASCII = ''.join(str(ord(c)) for c in message)

    while not secret or not partialPublicKey or not r:
        try:
            secret, partialPublicKey, r = retrievePublicKeys(auth1)
        except:
            print("An error has occured")
            count += 1
        if count == 10:
            print("Please restart the server")

    commitmentInfo = str(secret) + "||" + str(partialPublicKey) + "||" + str(r)
    ## Convert the commitmentInfo into bytes and send to server
    commitmentInfo = str.encode(str(commitmentInfo))

    auth1 = startSocket()
    sendCommitment(commitmentInfo,auth1)

    auth1.close()

if __name__ == "__main__":
    main()












