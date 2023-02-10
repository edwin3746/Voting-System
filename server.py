from tinyec import registry
from threading import Thread
#from Crypto.Cipher import AES
import datetime
import secrets
import socket
import time

## Pip install tinyec

server_address = ('127.0.0.1', 7777)

## This function is for countdown to indicate when to decrypt and tabulate the data
def error():
    print("Oops! Something gone wrong!")

def socketSetup(publicKeyinBytes,candidateNames,votingEnd):
    ## Create socket object and send public key over
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(server_address)
    server.listen(1)
    while True:
        try:
            print(f"Waiting for client to retrieve Public Information")
            connection, client_address = server.accept()
            print("Connection From : ", client_address)
            while True:
                msgCode = connection.recv(1024).decode("utf-8")
                if msgCode == "Requesting Voting Deadline":
                    connection.send(votingEnd)
                elif msgCode == "Requesting Public Key":
                    connection.send(publicKeyinBytes)
                elif msgCode == "Requesting Candidate Names":
                    connection.send(candidateNames)
                else:
                    connection.send(b"An error has occured!")
        except Exception as e:
            print("An error has occured: ", e)

def collateVotes():
    ## Decrypting and count all the votes
    printf("Decrypt!")

def generateKeys():
    ## Curve with 192-bit security
    ecc_curve = registry.get_curve('secp384r1')
    private_key = secrets.randbelow(ecc_curve.field.n)
    public_key = private_key * ecc_curve.g

    if not private_key or not public_key:
        error()

    return public_key, private_key

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

    ## Generate keys using ElGamal
    public_key, private_key = generateKeys()

    ## Convert public key string to bytes to be send over using Socket
    public_key_bytes = str.encode(str(public_key.x) + "||" + str(public_key.y))

    ## Server running in the background
    server = Thread(target = socketSetup, args=(public_key_bytes,candidateNames,votingEnd))
    server.start()

    ## Sleep until the time is up and server will shutdown and start to decrypt votes
    timeDifference = votingEndDate - datetime.datetime.now()
    timeDifferenceinSec = timeDifference.total_seconds()
    time.sleep(timeDifferenceinSec)
    server.stop()
    collateVotes()

if __name__ == "__main__":
    main()
