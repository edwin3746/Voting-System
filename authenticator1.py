import socket
import time
import os
import ssl
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes
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
    partialPrivateKey = pow(g, partialx, p)

    ## Commitment
    r = generate_r(q)
    secret = (pow(g,partialPrivateKey,p) * pow(partialPrivateKey, r, p)) % p
    return secret,partialPrivateKey,r

def startSocket():
    auth1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    auth1 = ssl.wrap_socket(auth1, keyfile=currentPath+"\key.pem", certfile=currentPath+"\certificate.pem")

    auth1.bind(auth1_address)
    return auth1

def main():
    auth1 = startSocket()
    secret = ""
    partialPrivateKey = ""
    r = ""
    count = 0

    while not secret or not partialPrivateKey or not r:
        try:
            secret,partialPrivateKey,r = retrievePublicKeys(auth1)
        except:
            print("An error has occured")
            count += 1
        if count == 10:
            print("Please restart the server")

    commitmentInfo = str(secret) + "||" + str(partialPrivateKey) + "||" + str(r)
    ## Convert the commitmentInfo into bytes and send to server
    commitmentInfo = str.encode(str(commitmentInfo))

    auth1 = startSocket()
    sendCommitment(commitmentInfo,auth1)

    auth1.close()

if __name__ == "__main__":
    main()












