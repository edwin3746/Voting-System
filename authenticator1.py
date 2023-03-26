import socket
import time
import os
import ssl
import jwt
import pyminizip
import pyautogui
import struct

from hashlib import sha256
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes, random
from server import server_address as server_address
from server import decryptVotes_address as decryptVotes_address

## Pip install pycryptodomex
## pip install pyJWT

currentPath = os.getcwd()

## Define params for JWT & generate token with payload and secret key
params = {'username':'authenticator1'}
token = jwt.encode(params, 'sEcUrEkEy', algorithm='HS256')
token = str.encode(token)

def generate_r(q):
    r = number.getRandomRange(2, q-2)
    return r

def retrievePublicKeys(receivePubKeyInfo):
    global token
    count = 0
    receivePubKeyInfo.connect(server_address)
    pubKeyInfo = ""
    p = ""
    q = ""
    g = ""
    verified = False

    ## Sending token to Server to verify itself
    while not verified:
        receivePubKeyInfo.send(token)
        while True:
            msgCode = receivePubKeyInfo.recv(1024).decode("utf-8")
            if msgCode == "Valid user!":
                verified = True
                break
            else:
                raise Exception()

    while not pubKeyInfo or not p or not q or not g:
        receivePubKeyInfo.send(b'Retrieve public key parameters')
        pubKeyInfo = receivePubKeyInfo.recv(8192*10).decode("utf-8")
        print("Recevived Public Key Parameters!")
        p = int(pubKeyInfo.split("||")[0])
        q = int(pubKeyInfo.split("||")[1])
        g = int(pubKeyInfo.split("||")[2])
        count += 1
        if count == 10:
            raise Exception()
    if p and q and g:
        print("------- Parameters Received -------")
        print("Value of p : " + str(p))
        print("Value of q : " + str(q))
        print("Value of g : " + str(g))
        print("------- End of Parameters -------")
        receivePubKeyInfo.send(b"Received Params!")

    while True:
        if receivePubKeyInfo.recv(1024).decode("utf-8") == "Partial Private Key Generated Complete!":
            time.sleep(5)
            break

    ## Generate part of public key here (g^x mod p)
    partialx = number.getRandomRange(1,int(q))
    print("Private Key Generated!")
    partialPublicKey = pow(g, partialx, p)
    print("Partial Public Key Generated!")

    print("------- Authenticator 1 Partial Key Pair Values -------")
    print("Value of Authenticator 1's Partial Public Key : " + str(partialPublicKey))
    print("Value of Authenticator 1's Partial Private Key : " + str(partialx))

    ## Commitment
    r = generate_r(q)
    print("Value of Authenticator 1 Random R : " + str(r))
    print("------- End of Partial Key Pair Values -------")
    secret = (pow(g,partialPublicKey,p) * pow(partialPublicKey, r, p)) % p
    print("Commitment for Partial Public Key Generated!")
    print("------- Commitment Values -------")
    print("Value of Authenticator 1 Commitment : " + str(secret))
    print("------- End of Commitment Values -------")

    return partialx,secret,partialPublicKey,r, p, q, g

def sendCommitment(commitmentValue,server):
    global token
    count = 0
    verified = False
    server.connect(server_address)

    print("Sending Commitment to Server!")
    ## Sending token to Server to verify itself
    ## Submit commitmentValue first if verified
    while not verified:
        server.sendall(token)
        while True:
            msgCode = server.recv(1024).decode("utf-8")
            if msgCode == "Connection is secure":
                server.sendall(commitmentValue)
            if msgCode == "Commitment Received":
                server.close()
                verified = True
                break
            count += 1
            if count == 10:
                raise Exception()

def sendEncryptedPartialPublicKey(partialPublicKeyInfo,server):
    global token
    count = 0
    verified = False
    server.connect(server_address)

    print("Sending Encrypted Partial Public Key to Server!")
     ## Sending token to Server to verify itself
    ## Submit partial Public Key if verified
    while not verified:
        server.send(token)
        while True:
            msgCode = server.recv(1024).decode("utf-8")
            if msgCode == "Connection is secure":
                server.sendall(partialPublicKeyInfo)
            if msgCode == "Valid":
                server.close()
                verified = True
                break
            count += 1
            if count == 10:
                raise Exception()

def sendSignature(server, p, q, g, partialPublicKey, privateKeyFilename, encryptedZipFile):
    global token
    connected = False
    print("Voting in progress..")
    while not connected:
        try:
            server.connect(decryptVotes_address)
            print("Connected")
            server.send(token)
            msgCode = server.recv(1024).decode("utf-8")
            if msgCode == "Connection is secure":

                # retrieve private key from encrypted zip file
                # unlocking the password protected zip file
                for i in range(3):
                    passwordAttempt = pyautogui.password(text='Enter password', title='Authenticator 1', default='',
                                                         mask='*')
                    try:
                        pyminizip.uncompress(encryptedZipFile, passwordAttempt, "", 0)
                        with open(privateKeyFilename) as file:
                            privateKey = int(file.read())
                        break
                    except:
                        print(f"Wrong password, you have {3 - i - 1} tries left")

                else:
                    print("Max tries reached, quitting program.")

                # generate signature with private key
                print("Creating Schnorr signature with private key")
                e, s = schnorrSignature(p, q, g, partialPublicKey, privateKey, "Auth1")
                print("------- Authenticator 1 Schnorr signature -------")
                print("Value of Authenticator 1's e : " + str(e))
                print("Value of Authenticator 1's s : " + str(s))
                print("------- End of Authenticator 1 Schnorr signature -------")
                privateKeySignature = e + "||" + s
                privateKeySignature = str.encode(privateKeySignature + "||" + str(partialPublicKey))
                server.send(privateKeySignature)
                break
        except ConnectionRefusedError:
            time.sleep(2)

    while True:
        msgCode = server.recv(1024).decode("utf-8")
        if msgCode == "Verification complete":
            decryptEncryptedVotes(server, privateKey, p, g)

def decryptEncryptedVotes(server, privateKey, p, g):
    decryptedText = ""
    encryptedVote = server.recv(8192).decode("utf-8")
    splitEncryptedVote = encryptedVote.split("||")
    print("Decrypting votes")
    for i in range(0, len(splitEncryptedVote)-1):
        decryptedText = decryptedText + str(partialDecrypt(int(splitEncryptedVote[i]), privateKey,p)) + "||"
    print("------- Partially Decrypted a (Authenticator 1) -------")
    print("Value of partially decrypted a value by Authenticator 1 : " + str(decryptedText))
    print("------- End of Partially Decrypted a (Authenticator 1) -------")
    print("Votes are decrypted.. Sending back to server")
    sendDecryptedVotes(server, decryptedText)

def sendDecryptedVotes(server, decryptedText):
    decryptedText = str.encode(str(decryptedText))
    server.send(decryptedText)
    print("Completed!. Exiting the program in 5 seconds")
    time.sleep(5)
    server.close()
    exit()

def verifySchnorr(p, g, s, e, publicKey, message):
    message = ''.join(str(ord(c)) for c in message)
    xv = pow(pow(g, s, p) * pow(publicKey, e, p), 1, p)
    ev = hashThis(xv, message) % p
    return ev == e

# partial decrypt function
def partialDecrypt(a, privateKey, p):
    return pow(a, p-1-privateKey, p)

# creating the Schnorr signature
def schnorrSignature(p, q, g, publicKey, privateKey, message):
    message = ''.join(str(ord(c)) for c in message)
    r = random.randint(1, q - 1)
    x = pow(g, r, p)
    e = hashThis(x, publicKey, message) % p
    s = pow((r - (privateKey * e)), 1, p - 1)
    return str(e), str(s)

# sample hash function
def hashThis(r, publicKey, message):
    hash=sha256()
    hash.update(str(r).encode())
    hash.update(struct.pack("I", len(str(publicKey))))
    hash.update(str(publicKey).encode())
    hash.update(struct.pack("I", len(message)))
    hash.update(message.encode())
    return int(hash.hexdigest(),16)

def startSocket():
    port = number.getRandomRange(1, 65536)
    auth1_address = ('127.0.0.2',port)
    auth1Connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth1Connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    auth1Connection.bind(auth1_address)

    auth1TLS = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    auth1TLS.load_verify_locations(cafile="server.crt")

    auth1 = auth1TLS.wrap_socket(auth1Connection, server_hostname="GodVote")

    return auth1

def main():
    auth1 = startSocket()
    secret = ""
    partialPublicKey = ""
    r = ""
    privateKey = ""
    count = 0

    # password encrypted zip file
    privateKeyFilename = "secret_key_auth1.txt"
    encryptedZipFile = "password_protected_auth1.zip"

    while not secret or not partialPublicKey or not r or not privateKey:
        try:
            privateKey, secret, partialPublicKey, r, p, q, g = retrievePublicKeys(auth1)
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

    # user will enter a password
    userPassword = pyautogui.password(text='Enter password', title='Authenticator 1', default='', mask='*')
    with open(privateKeyFilename, 'w') as file:
        file.write(str(privateKey))
    pyminizip.compress(privateKeyFilename, None, encryptedZipFile, userPassword, 5)
    userPassword = ""

    auth1 = startSocket()
    sendCommitment(secret,auth1)
    auth1.close()
    time.sleep(10)

    auth1 = startSocket()
    sendEncryptedPartialPublicKey(partialPublicKeyInfo,auth1)
    auth1.close()

    auth1 = startSocket()
    ## Generate and send ZKP signature to verify that it has private key
    sendSignature(auth1, p, q, g, partialPublicKey, privateKeyFilename, encryptedZipFile)

if __name__ == "__main__":
    main()
