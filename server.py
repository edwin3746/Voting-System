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

def socketSetup(publicKeyParams,publicKeyBytes,candidateNames,votingEnd):
    ## Create socket object and send public key over
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(server_address)
    server.listen(1)
    while True:
        try:
            print(f"Waiting for client to retrieve Public Information")
            connection, client_address = server.accept()
            print("Connection From : ", client_address)
            if client_address[0] == "127.0.0.2" or client_address[0] == "127.0.0.3":
                print("Yes")
                msgCode = connection.recv(1024).decode("utf-8")
                if msgCode == "Retrieve public key parameters":
                    print(publicKeyParams)
                    connection.sendall(publicKeyParams)
            else:
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

    ## Generate the keys required for ElGamal
    partialPrivateKey = number.getRandomRange(2, q-2)
    publicKey = pow(g, partialPrivateKey, p)

    ## Convert public key string and params to bytes to be send over using Socket
    publicKeyBytes = str.encode(str(publicKey))
    publicKeyParam = str.encode(str(q))

    sever = Thread(target=startServer)
    ## Server running in the background
    server = Thread(target = socketSetup, args=(publicKeyParam,publicKeyBytes,candidateNames,votingEnd))
    server.start()

    ## Sleep until the time is up and server will shutdown and start to decrypt votes
    timeDifference = votingEndDate - datetime.datetime.now()
    timeDifferenceinSec = timeDifference.total_seconds()
    time.sleep(timeDifferenceinSec)
    server.stop()
    collateVotes()

if __name__ == "__main__":
    main()
