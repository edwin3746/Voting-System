import socket
import time
import os
import ssl
from hashlib import sha256

from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes, random
from server import server_address as server_address
from server import decryptVotes_address as decryptVotes_address

## Pip install pycryptodomex


currentPath = os.getcwd()

def generate_r(q):
    r = number.getRandomRange(2, q-2)
    return r

def sendCommitment(commitmentValue,server):
    count = 0
    server.connect(server_address)

    print("Sending Commitment to Server!")
    ## Submit commitmentValue first
    while True:
        if server.recv(1024).decode("utf-8") == "Connection is secure":
            server.sendall(commitmentValue)
        if server.recv(1024).decode("utf-8") == "Commitment Received":
            server.close()
            break
        count += 1
        if count == 10:
            raise Exception()

def sendEncryptedPartialPublicKey(partialPublicKeyInfo,server):
    count = 0
    server.connect(server_address)

    print("Sending Encrypted Partial Public Key to Server!")
    while True:
        if server.recv(1024).decode("utf-8") == "Connection is secure":
            server.sendall(partialPublicKeyInfo)
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

    while not pubKeyInfo or not p or not q or not g:
        receivePubKeyInfo.sendall(b'Retrieve public key parameters')
        pubKeyInfo = receivePubKeyInfo.recv(8192*10).decode("utf-8")
        print("Recevived Public Key Parameters!")
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
            time.sleep(10)
            receivePubKeyInfo.close()
            break

    ## Generate part of public key here (g^x mod p)
    partialx = number.getRandomRange(2,int(q)-2)
    print("Private Key Generated!")
    partialPublicKey = pow(g, partialx, p)
    print("Partial Public Key Generated!")

    ## Commitment
    r = generate_r(q)
    secret = (pow(g,partialPublicKey,p) * pow(partialPublicKey, r, p)) % p
    print("Commitment for Partial Public Key Generated!")
    return partialx,secret,partialPublicKey,r, p, q, g

def sendSignature(privateKeySignature, server, privateKey, p):
    connected = False
    print("Voting in progress..")
    while not connected:
        try:
            server.connect(decryptVotes_address)
            msgCode = server.recv(1024).decode("utf-8")
            if msgCode == "Connection is secure":
                server.send(privateKeySignature)
                break
        except ConnectionRefusedError:
            time.sleep(5)
    while True:
        msgCode = server.recv(1024).decode("utf-8")
        if msgCode == "Verification complete":
            decryptEncryptedVotes(server, privateKey, p)

def decryptEncryptedVotes(server, privateKey, p):
    decryptedText = ""
    encryptedVote = server.recv(8192).decode("utf-8")
    splitEncryptedVote = encryptedVote.split("||")

    print("Decrypting votes")
    for i in range(0, len(splitEncryptedVote)-1):
        decryptedText = decryptedText + str(partialDecrypt(int(splitEncryptedVote[i]), privateKey,p)) + "||"

    print("Votes are decrypted.. Sending back to server")
    sendDecryptedVotes(server, decryptedText)

def sendDecryptedVotes(server, decryptedText):
    decryptedText = str.encode(str(decryptedText))
    server.send(decryptedText)
    print("Completed!. Exiting the program in 5 seconds")
    time.sleep(5)
    exit()

# partial decrypt function
def partialDecrypt(a, privateKey, p):
    return pow(a, p-1-privateKey, p)

# creating the Schnorr signature
def schnorrSignature(p, q, g, privateKey, message):
    messageInASCII = ''.join(str(ord(c)) for c in message)
    r = random.randint(1, q - 1)
    x = pow(g, r, p)
    e = hashThis(x, messageInASCII) % p
    s = pow((r - (privateKey * e)), 1, p - 1)
    return str(e), str(s)

def verifySchnorr(p, g, s, e, publicKey, message):
    messageInASCII = ''.join(str(ord(c)) for c in message)
    rv = pow(pow(g, s, p) * pow(publicKey, e, p), 1, p)
    ev = hashThis(rv, messageInASCII) % p
    return ev == e

# sample hash function
def hashThis(r, message):
    hash=sha256();
    hash.update(str(r).encode());
    hash.update(message.encode());
    return int(hash.hexdigest(),16)

def startSocket():
    port = number.getRandomRange(1, 65536)
    auth2_address = ('127.0.0.3',port)
    auth2Connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth2Connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    auth2Connection.bind(auth2_address)

    auth2TLS = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    auth2TLS.load_verify_locations(cafile="server.crt")

    auth2 = auth2TLS.wrap_socket(auth2Connection, server_hostname="greek")

    return auth2

def main():
    auth2 = startSocket()
    secret = ""
    partialPublicKey = ""
    r = ""
    privateKey = ""
    count = 0

    # this message is to determine which server/authenticator sent the Schnorr signature
    message = "auth2"
    messageInASCII = ''.join(str(ord(c)) for c in message)

    while not secret or not partialPublicKey or not r or not privateKey:
        try:
            privateKey,secret,partialPublicKey,r,p,q,g = retrievePublicKeys(auth2)
        except:
            print("An error has occured")
            count += 1
        if count == 10:
            print("Please restart the server")
            exit()

    partialPublicKeyInfo = str(partialPublicKey) + "||" + str(r)
    ## Convert the commitmentInfo into bytes and send to server
    partialPublicKeyInfo = str.encode(partialPublicKeyInfo)
    secret = str.encode(str(secret))

    auth2 = startSocket()
    sendCommitment(secret,auth2)

    time.sleep(15)
    auth2 = startSocket()
    sendEncryptedPartialPublicKey(partialPublicKeyInfo,auth2)
    auth2.close()

    auth2 = startSocket()
    e, s = schnorrSignature(p, q, g, privateKey, 'Auth2')
    privateKeySignature = e + "||" + s
    privateKeySignature = str.encode(privateKeySignature)
    sendSignature(privateKeySignature, auth2, privateKey, p)

if __name__ == "__main__":
    main()

