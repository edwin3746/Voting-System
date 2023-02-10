import socket
import time
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes

## Pip install pycryptodomex

server_address = ('127.0.0.1',7777)
port = number.getRandomRange(1, 65536)
auth2_address = ('127.0.0.3',port)

def generate_r(q):
    r = number.getRandomRange(2, q-2)
    return r

def sendCommitment(commitmentInfo,server):
    server.connect(server_address)
    if server.recv(1024).decode("utf-8") == "Connection is secure":
        server.sendall(commitmentInfo)
    if server.recv(1024).decode("utf-8") == "Valid":
        server.close()

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

    msgCode = receivePubKeyInfo.recv(1024).decode("utf-8")
    while msgCode != "Partial Private Key Generated Complete!":
        print(wait)
        wait += "."
    print("Done")
    receivePubKeyInfo.close()

    ## Generate part of private key here (g^x mod p)
    partialx = number.getRandomRange(2,int(q)-2)
    partialPrivateKey = pow(g, partialx, p)

    ## Commitment
    r = generate_r(q)
    secret = (pow(g,partialPrivateKey,p) * pow(partialPrivateKey, r, p)) % p
    return secret,partialPrivateKey,r

def main():
    auth2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth2.bind(auth2_address)
    secret = ""
    partialPrivateKey = ""
    r = ""

    secret,partialPrivateKey,r = retrievePublicKeys(auth2)

    print(secret)
    #commitmentInfo = str(secret) + "||" + str(partialPrivateKey) + "||" + str(r)
    ## Convert the commitmentInfo into bytes and send to server
    #commitmentInfo = str.encode(str(commitmentInfo))
    #sendCommitment(commitmentInfo,auth1)

    auth2.close()

if __name__ == "__main__":
    main()







