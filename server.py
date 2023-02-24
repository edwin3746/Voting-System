import threading
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.number import isPrime
import datetime
import socket
import time
import random
import ssl
import os

## Pip install pycryptodomex

server_address = ('127.0.0.1', 7777)
receiveVote_address = ('127.0.0.1', 8888)
currentPath = os.getcwd()
votes = []
voters = []

## This function is for countdown to indicate when to decrypt and tabulate the data
def error():
    print("Oops! Something gone wrong!")

def setupServer(i):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    if i == 1:
        server_socket.bind(server_address)

    elif i == 2:
        server_socket.bind(receiveVote_address)

    server_socket.listen()
    return ssl_context, server_socket

def authenticatorPartialPublicKey(ssl_context,server,auth1Secret,auth2Secret,g,p):
    auth1Count = 0
    auth2Count = 0
    auth1PartialPrivateKey = ""
    auth1R = ""
    auth2PartialPrivateKey = ""
    auth2R = ""

    print("Waiting for Authenticator to send Partial Public Key / R")
    while auth1Count == 0 or auth2Count == 0:
        ## Accept all incoming conections
        connection, client_address = server.accept()
        ssl_con = ssl_context.wrap_socket(connection, server_side=True)
        ## Ensure that the connection to retrieve q is only this 2 IP address
        if client_address[0] == "127.0.0.2" or client_address[0] == "127.0.0.3":
            ssl_con.sendall(b'Connection is secure')
            msgCode = ssl_con.recv(8192).decode("utf-8")
            if client_address[0] == "127.0.0.2":
                auth1PartialPublicKey = msgCode.split("||")[0]
                auth1R = msgCode.split("||")[1]
                if str((pow(g,int(auth1PartialPublicKey),p) * pow(int(auth1PartialPublicKey),int(auth1R),p)) % p) == auth1Secret:
                    auth1Count = 1
                    print("Authenticator 1 partial public key is valid!")
                    ssl_con.sendall(b'Valid')
                else:
                    print("Error! Maybe someone else tried to send partial public key!")
                    ssl_con.sendall(b'Invalid')

            elif client_address[0] == "127.0.0.3":
                auth2PartialPublicKey = msgCode.split("||")[0]
                auth2R = msgCode.split("||")[1]
                if str((pow(g,int(auth2PartialPublicKey),p) * pow(int(auth2PartialPublicKey),int(auth2R),p)) % p) == auth2Secret:
                    auth2Count = 1
                    print("Authenticator 2 partial public key is valid!")
                    ssl_con.sendall(b'Valid')
                else:
                    print("Error! Maybe someone else tried to send partial public key!")
                    ssl_con.sendall(b'Invalid')
        else:
            print("Invalid Connections!")
    server.close()
    return auth1PartialPublicKey, auth2PartialPublicKey

def retrieveCommitmentValues(ssl_context, server):
    auth1Count = 0
    auth2Count = 0
    auth1Secret = ""
    auth2Secret = ""

    print("Waiting for Authenticator to send Commitment value")
    while auth1Count == 0 or auth2Count == 0:
        ## Accept all incoming conections
        connection, client_address = server.accept()
        ssl_con = ssl_context.wrap_socket(connection, server_side=True)
        ## Ensure that the connection to retrieve q is only this 2 IP address
        if client_address[0] == "127.0.0.2" or client_address[0] == "127.0.0.3":
            ssl_con.sendall(b'Connection is secure')
            msgCode = ssl_con.recv(8192).decode("utf-8")
            if client_address[0] == "127.0.0.2":
                auth1Secret = msgCode
                auth1Count += 1
                print("Authenticator 1's commitment value recieved!")
                ssl_con.sendall(b'Commitment Received')
            elif client_address[0] == "127.0.0.3":
                auth2Secret = msgCode
                auth2Count += 1
                print("Authenticator 2's commitment value recieved!")
                ssl_con.sendall(b'Commitment Received')
            else:
                print("Error! Maybe someone else tried to send commitment value!")
                ssl_con.sendall(b'Invalid')
        else:
            print("Invalid Connections!")

    return auth1Secret,auth2Secret

def sendParamsToAuthenticator(publicKeyParamBytes, connection, client_address):
    while True:
        msgCode = connection.recv(1024).decode("utf-8")
        if msgCode == "Received Q!" and client_address[0] == "127.0.0.2":
            print("Authenticator 1 received Q!")
            break
        elif msgCode == "Received Q!" and client_address[0] == "127.0.0.3":
            print("Authenticator 2 received Q!")
            break
        else:
            connection.send(publicKeyParamBytes)

def syncConnectionToAuthenticator(publicKeyParamBytes):
    ## Create socket object and send public param q over
    ssl_context, server = setupServer(1)
    auth1Count = 0
    auth2Count = 0
    connections = []
    threads = []
    stopSync = threading.Event()

    print("Waiting for Authenticator to retrieve Public Q")
    while auth1Count == 0 or auth2Count == 0:
        ## Accept all incoming conections
        connection, client_address = server.accept()
        ssl_conn = ssl_context.wrap_socket(connection,server_side=True)
        ## Ensure that the connection to retrieve q is only this 2 IP address
        if client_address[0] == "127.0.0.2" or client_address[0] == "127.0.0.3":
            thread = threading.Thread(target = sendParamsToAuthenticator, args=(publicKeyParamBytes, ssl_conn, client_address))
            threads.append(thread)
            thread.start()
            connections.append(ssl_conn)
            if client_address[0] == "127.0.0.2":
                auth1Count = 1
            elif client_address[0] == "127.0.0.3":
                auth2Count = 1
            if auth1Count == 1 and auth2Count == 1:
                break
        else:
            print("Invalid Connections!")

    ## Notify the threads to stop
    stopSync.set()
    ## Send the message for the threads to continue
    for con in connections:
        con.send(b"Partial Private Key Generated Complete!")
    for thread in threads:
        thread.join()
    return ssl_context,server

def socketSetupForPublic(ssl_context,server,publicKeyBytes,candidateNames,votingEnd, pParamBytes, gParamBytes, qParamBytes):
    ## Socket will keep releasing public information to voters who connect
    while True:
        try:
            print("Waiting for client to retrieve Public Information")
            connection, client_address = server.accept()
            ssl_conn = ssl_context.wrap_socket(connection,server_side=True)
            print("Connection From : ", client_address)
            while True:
                msgCode = ssl_conn.recv(1024).decode("utf-8")
                if msgCode == "Requesting Voting Deadline":
                    ssl_conn.sendall(votingEnd)
                elif msgCode == "Requesting Public Key":
                    ssl_conn.sendall(publicKeyBytes)
                elif msgCode == "Requesting Candidate Names":
                    ssl_conn.sendall(candidateNames)
                elif msgCode == "Requesting Public P":
                    ssl_conn.sendall(pParamBytes)
                elif msgCode == "Requesting Public G":
                    ssl_conn.sendall(gParamBytes)
                elif msgCode == "Requesting Public Q":
                    ssl_conn.sendall(qParamBytes)
                else:
                    ssl_conn.sendall(b"An error has occured!")
        except Exception as e:
            print("An error has occured: ", e)

def receiveVotes(ssl_context,server,votingEnd,g,p):
    ## Socket will keep receiving votes from voters who connect
    global voters
    global votes
    while True:
        print("Waiting for votes")
        ## Accept all incoming connections
        connection, client_address = server.accept()
        ssl_conn = ssl_context.wrap_socket(connection,server_side=True)
        print("Connection From For Votes: ", client_address)
        if client_address not in voters:
            ssl_conn.sendall(b"Connection is secure")
            votersCommitment = ssl_conn.recv(8192).decode("utf-8")
            if votersCommitment:
                ssl_conn.sendall(b"Commitment received!")
                voters.append(client_address)
                votersEncryptedVote = ssl_conn.recv(8192).decode("utf-8")
            if votersCommitment and votersEncryptedVote:
                commitmentValues = votersCommitment.split("***")
                encryptedVotes = votersEncryptedVote.split("***")
                for i in range (0,len(commitmentValues)-1):
                    if commitmentValues[i].split("||")[0] == str(pow(g,int(encryptedVotes[i].split("||")[0]) + int(encryptedVotes[i].split("||")[1]),p) * pow(int(encryptedVotes[i].split("||")[0]) + int(encryptedVotes[i].split("||")[1]),int(commitmentValues[i].split("||")[1]),p) % p):
                        ssl_conn.sendall(b'Vote is valid!')
                        votes.append(votersEncryptedVote)
                        break
                    else:
                        ssl_conn.sendall(b'Vote is tampered!')
        else:
            ssl_conn.send(b'You have already voted. Results will be released at ' + votingEnd)


def collateVotes():
    ## Decrypting and count all the votes
    print("Decrypt!")

def generate_primes():
    p = 0
    s = 0
    q = number.getPrime(256)

    while not isPrime(p):
        while not p.bit_length() == 2048:
            s = random.randrange(2**1790, 2**1791)
            p = 2 * q * s + 1
        s += 1
        p = 2 * q * s + 1

    return p, q

def generate_g(p, q):
    g = 0
    ## Check if g is a generator of a finite group of prime order q
    while not g > 1 or not pow(g,q,p):
        h = number.getRandomRange(2, p-2)
        g = pow(h, (p-1)//q, p)
    return g

# partial decrypt function
def partialDecrypt(a, privateKey, p):
    return pow(a, p-1-privateKey, p)

# full decrypt function, assuming 3 authenticators
def fullDecrypt(partialDecrypted1, partialDecrypted2, partialDecrypted3, p, ciphertext):
    # can replace ciphertext with b if you want
    a, b = ciphertext
    return pow(partialDecrypted1 * partialDecrypted2 * partialDecrypted3 * b, 1, p)

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

# verification of Schnorr signature
def verifySchnorr(p, g, s, e, publicKey, message):
    rv = pow(pow(g, s, p) * pow(publicKey, e, p), 1, p)
    ev = hashThis(rv, message) % p
    return ev == e

def main():
    ## Retrieve the number of candidates and their names respectively
    candidates = []
    candidateNames = ""
    num = ""
    name = ""
    votingHours = ""

    while num == "":
        num = input("Enter the number of candidates : ")
    for loop in range(int(num)):
        while name == "":
            name = input("Enter the name of candidate " + str(loop+1) + ":" )
            candidates.append(name)
        name = ""

    for names in candidates:
        candidateNames += names + "||"

    ## Convert name to bytes
    candidateNames = str.encode(candidateNames)

    while votingHours == "":
        votingHours = input ("Enter the number of hours allowed to vote : ")

    ## Convert to hours and then to bytes
    votingEndDate = datetime.datetime.now() + datetime.timedelta(hours = int(votingHours))
    votingEnd = str.encode(votingEndDate.strftime("%Y-%m-%d %H:%M:%S"))

    print("Initializing....Generating parameters")
    ## Generate the parameters using ElGamal
    p, q = generate_primes()
    g = generate_g(p, q)

    print("Parameters generated!")
    ## Convert q to bytes to be send over to Authenticator using Socket
    publicKeyParam = str(p) + "||" + str(q) + "||" + str(g) + "||"
    publicKeyParamBytes = str.encode(publicKeyParam)
    ssl_context, server = syncConnectionToAuthenticator(publicKeyParamBytes)
    print("Partial Public Key is generated on individual Authenticator")

    ## Retrieve the commitment values from Authenticators
    auth1Commitment, auth2Commitment = retrieveCommitmentValues(ssl_context,server)
    partialPublicKey1, partialPublicKey2 = authenticatorPartialPublicKey(ssl_context,server,auth1Commitment,auth2Commitment,g,p)

    ## Generate the partial private key
    partialPrivateKey = number.getRandomRange(2, q-2)
    partialPublicKey3 = pow(g,partialPrivateKey,p)
    publicKey = pow(partialPublicKey3*int(partialPublicKey1)*int(partialPublicKey2), 1 , p)
    print("Public Key Generated!")

    ## Convert public key string and params to bytes to be send over using Socket
    publicKeyBytes = str.encode(str(publicKey))

    ## Convert p and g to bytes to be send over to client using Socket
    pParam = str(p)
    gParam = str(g)
    pParamBytes = str.encode(pParam)
    gParamBytes = str.encode(gParam)
    qParamBytes = str.encode(str(q))
    ## Server running in the background
    ssl_context,server = setupServer(1)
    sendInfoToVoters = threading.Thread(target = socketSetupForPublic, args=(ssl_context,server,publicKeyBytes,candidateNames,votingEnd, pParamBytes, gParamBytes, qParamBytes))
    sendInfoToVoters.start()

    ssl_context1,receiveVote = setupServer(2)
    receiveServer = threading.Thread(target = receiveVotes, args=(ssl_context1,receiveVote,votingEnd,int(gParam),int(pParam)))
    receiveServer.start()

    ## Sleep until the time is up and server will shutdown and start to decrypt votes
    timeDifference = votingEndDate - datetime.datetime.now()
    timeDifferenceinSec = timeDifference.total_seconds()
    time.sleep(timeDifferenceinSec)
    sendInfoToVoters.stop()
    receiveServer.stop()
    server.close()
    collateVotes()

if __name__ == "__main__":
    main()

