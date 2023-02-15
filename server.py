import threading
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes
from Crypto.Util.number import isPrime
import datetime
import socket
import time
import random

## Pip install pycryptodomex

server_address = ('127.0.0.1', 7777)
votes = {}
voters = []

## This function is for countdown to indicate when to decrypt and tabulate the data
def error():
    print("Oops! Something gone wrong!")

def setupServer():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(server_address)
    server.listen(2)
    return server

def authenticatorPartialPrivateKey(g, p):
    server = setupServer()
    auth1Count = 0
    auth2Count = 0
    auth1Secret = ""
    auth1PartialPrivateKey = ""
    auth1R = ""
    auth2Secret = ""
    auth2PartialPrivateKey = ""
    auth2R = ""

    print("Waiting for Authenticator to send Partial Private Key / R / Commitment value")
    while auth1Count == 0 or auth2Count == 0:
        ## Accept all incoming conections
        connection, client_address = server.accept()
        ## Ensure that the connection to retrieve q is only this 2 IP address
        if client_address[0] == "127.0.0.2" or client_address[0] == "127.0.0.3":
            connection.sendall(b'Connection is secure')
            msgCode = connection.recv(8192).decode("utf-8")
            if client_address[0] == "127.0.0.2":
                auth1Secret = msgCode.split("||")[0]
                auth1PartialPrivateKey = msgCode.split("||")[1]
                auth1R = msgCode.split("||")[2]
                if (pow(g,int(auth1PartialPrivateKey),p) * pow(int(auth1PartialPrivateKey),int(auth1R),p)) % p:
                    auth1Count = 1
                    connection.sendall(b'Valid')
                else:
                    connection.sendall(b'Invalid')

            elif client_address[0] == "127.0.0.3":
                auth2Secret = msgCode.split("||")[0]
                auth2PartialPrivateKey = msgCode.split("||")[1]
                auth2R = msgCode.split("||")[2]
                if (pow(g,int(auth2PartialPrivateKey),p) * pow(int(auth2PartialPrivateKey),int(auth2R),p)) % p:
                    auth2Count = 1
                    connection.sendall(b'Valid')
                else:
                    connection.sendall(b'Invalid')
        else:
            print("Invalid Connections!")
    return auth1PartialPrivateKey, auth2PartialPrivateKey

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
            connection.sendall(publicKeyParamBytes)

def syncConnectionToAuthenticator(publicKeyParamBytes):
    ## Create socket object and send public param q over
    server = setupServer()
    auth1Count = 0
    auth2Count = 0
    connections = []
    threads = []
    stopSync = threading.Event()

    print("Waiting for Authenticator to retrieve Public Q")
    while auth1Count == 0 or auth2Count == 0:
        ## Accept all incoming conections
        connection, client_address = server.accept()
        ## Ensure that the connection to retrieve q is only this 2 IP address
        if client_address[0] == "127.0.0.2" or client_address[0] == "127.0.0.3":
            thread = threading.Thread(target = sendParamsToAuthenticator, args=(publicKeyParamBytes, connection, client_address))
            threads.append(thread)
            thread.start()
            connections.append(connection)
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
    server.close()

def socketSetupForPublic(server,publicKeyBytes,candidateNames,votingEnd, pParamBytes, gParamBytes):
    ## Socket will keep releasing public information to voters who connect
    while True:
        try:
            print("Waiting for client to retrieve Public Information")
            connection, client_address = server.accept()
            print("Connection From : ", client_address)
            while True:
                msgCode = connection.recv(1024).decode("utf-8")
                if msgCode == "Requesting Voting Deadline":
                    connection.sendall(votingEnd)
                elif msgCode == "Requesting Public Key":
                    connection.sendall(publicKeyBytes)
                elif msgCode == "Requesting Candidate Names":
                    connection.sendall(candidateNames)
                elif msgCode == "Requesting Public P":
                    connection.sendall(pParamBytes)
                elif msgCode == "Requesting Public G":
                    connection.sendall(gParamBytes)
                else:
                    connection.sendall(b"An error has occured!")
        except Exception as e:
            print("An error has occured: ", e)

def receiveVotes(server, votingEnd):
    ## Socket will keep receiving votes from voters who connect
    global voters
    global votes
    while True:
        ## Accept all incoming connections
        connection, client_address = server.accept()
        vote = connection.recv(1024).decode("utf-8")
        if client_address not in voters:
            ## NEED TO DO ZKP HERE!!!!!
            voters.append(client_address)
            votes[client_address] = vote
        else:
            connection.send(b'You have already voted. Results will be released at ' + votingEnd)


def collateVotes():
    ## Decrypting and count all the votes
    print("Decrypt!")

def generate_primes():
    p = 0
    q = number.getPrime(256)
    s = random.randrange(2**1790, 2**1791)

    ## Checks is p is prime and at least 2048 bits
    while not isPrime(p) or not p.bit_length() == 2048:
        p = 2 * q * s + 1
        s += 1
    return p, q

def generate_g(p, q):
    g = 0
    ## Check if g is a generator of a finite group of prime order q
    while not g > 1 or not pow(g,q,p):
        h = number.getRandomRange(2, p-2)
        g = pow(h, (p-1)//q, p)
    return g

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
    syncConnectionToAuthenticator(publicKeyParamBytes)

    ## Convert p and g to bytes to be send over to client using Socket
    pParam = str(p)
    gParam = str(g)
    pParamBytes = str.encode(pParam)
    gParamBytes = str.encode(gParam)


    ## Retrieve all the partial private keys from authenticators with commitment verified
    partialPrivateKey1, partialPrivateKey2 = authenticatorPartialPrivateKey(g, p)

    ## Generate the partial private key
    partialPrivateKey = number.getRandomRange(2, q-2)
    publicKey = pow(g, partialPrivateKey*int(partialPrivateKey1)*int(partialPrivateKey2), p)

    ## Convert public key string and params to bytes to be send over using Socket
    publicKeyBytes = str.encode(str(publicKey))

    ## Server running in the background
    server = setupServer()
    sendInfoToVoters = threading.Thread(target = socketSetupForPublic, args=(server,publicKeyBytes,candidateNames,votingEnd, pParamBytes, gParamBytes))
    sendInfoToVoters.start()
    receiveServer = threading.Thread(target = receiveVotes, args=(server,votingEnd))
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
