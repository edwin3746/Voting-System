from threading import Thread
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes
import datetime
import socket
import time

## Pip install tinyec
## Pip install pycryptodomex

server_address = ('127.0.0.1', 7777)

## This function is for countdown to indicate when to decrypt and tabulate the data
def error():
    print("Oops! Something gone wrong!")

def parseParamsToAuthenticator(publicKeyParamBytes):
    ## Create socket object and send public param q over
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(server_address)
    server.listen(1)
    auth1Count = 0
    auth2Count = 0
    while True:
        print (auth1Count)
        print (auth2Count)
        try:
            print("Waiting for Authenticator to retrieve Public Q")
            connection, client_address = server.accept()
            print("Connection From : ", client_address)
            while True:
                ## Ensure that the connection to retrieve q is only this 2 IP address
                if client_address[0] == "127.0.0.2" or client_address[0] == "127.0.0.3":
                    msgCode = connection.recv(1024).decode("utf-8")
                    print(msgCode)
                    ## If the IP address received q
                    if msgCode == "Received q" and client_address[0] == "127.0.0.2":
                        auth1Count += 1
                        break
                    elif msgCode == "Received q" and client_address[0] == "127.0.0.3":
                        auth2Count += 1
                        break
                    elif client_address[0] == "127.0.0.2" and auth1Count == 0 or client_address[0] == "127.0.0.3" and auth2Count == 0:
                        connection.sendall(publicKeyParamBytes)
        except Exception as e:
            print("An error has occured: ", e)
        ## If both Authenticator received q then close connection
        if auth1Count == 1 and auth2Count == 1:
            break
    server.close()

def socketSetupForPublic(publicKeyBytes,candidateNames,votingEnd):
    ## Create socket object and send public key over
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(server_address)
    server.listen(1)
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
                else:
                    connection.sendall(b"An error has occured!")
        except Exception as e:
            print("An error has occured: ", e)

def collateVotes():
    ## Decrypting and count all the votes
    printf("Decrypt!")

def generate_primes():
    p = number.getPrime(2048)
    q = number.getPrime(256)
    return p, q

def generate_g(p, q):
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

    ## Generate the parameters using ElGamal
    p, q = generate_primes()
    g = generate_g(p, q)

    ## Convert q to bytes to be send over to Authenticator using Socket
    publicKeyParam = str(p) + "||" + str(q) + "||" + str(g) + "||"
    publicKeyParamBytes = str.encode(publicKeyParam)
    parseParamsToAuthenticator(publicKeyParamBytes)


    ## Generate the partial private key
    partialPrivateKey = number.getRandomRange(2, q-2)
    publicKey = pow(g, partialPrivateKey, p)

    ## Convert public key string and params to bytes to be send over using Socket
    publicKeyBytes = str.encode(str(publicKey))

    ## Server running in the background
    server = Thread(target = socketSetup, args=(publicKeyBytes,candidateNames,votingEnd))
    server.start()

    ## Sleep until the time is up and server will shutdown and start to decrypt votes
    timeDifference = votingEndDate - datetime.datetime.now()
    timeDifferenceinSec = timeDifference.total_seconds()
    time.sleep(timeDifferenceinSec)
    server.stop()
    collateVotes()

if __name__ == "__main__":
    main()
