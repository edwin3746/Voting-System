from flask import Flask, redirect, url_for, render_template, request, jsonify, flash
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes
from server import server_address as server_address
from server import receiveVote_address as receiveVote_address
import hashlib
import socket
import time
import os
import ssl

## Pip install pycryptodomex

votePage = Flask(__name__)
currentPath = os.getcwd()
candidates = []
votingEnd = ""
pParamBytes = ""
gParamBytes = ""
qParamBytes = ""
vote_str = ""
publicKey = ""
randomIP = number.getRandomRange(4,200)
randomPort = number.getRandomRange(1, 65536)

def startSocket(i):
    client_address = ('127.0.0.'+str(randomIP), randomPort)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(client_address)

    serverTLS = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    serverTLS.load_verify_locations(cafile="server.crt")

    server = serverTLS.wrap_socket(server, server_hostname="greek")

    if i == 1:
        server.connect(server_address)
    elif i == 2:
        server.connect(receiveVote_address)
    return server

def generate_r(q):
    r = number.getRandomRange(2, q-2)
    return r

def retrieveServerInformation(receiveInfo):
    global publicKey
    global votingEnd
    global pParamBytes
    global gParamBytes
    global qParamBytes
    candidateNames = ""
    count = 0

    while not publicKey:
        receiveInfo.send(b'Requesting Public Key')
        publicKey = receiveInfo.recv(8192).decode("utf-8")
        count += 1
        if count == 10:
            raise Exception()

    count = 0

    while not votingEnd:
        receiveInfo.send(b'Requesting Voting Deadline')
        votingEnd = receiveInfo.recv(2048).decode("utf-8")
        count += 1
        if count == 10:
            raise Exception()

    count = 0

    while not candidateNames:
        receiveInfo.send(b'Requesting Candidate Names')
        candidateNames = receiveInfo.recv(2048).decode("utf-8")
        count += 1
        if count == 10:
            raise Exception()

    count = 0

    while not pParamBytes:
        receiveInfo.send(b'Requesting Public P')
        pParamBytes = receiveInfo.recv(2048).decode("utf-8")
        count += 1
        if count == 10:
            raise Exception()

    count = 0

    while not gParamBytes:
        receiveInfo.send(b'Requesting Public G')
        gParamBytes = receiveInfo.recv(2048).decode("utf-8")
        count += 1
        if count == 10:
            raise Exception()

    while not qParamBytes:
        receiveInfo.send(b'Requesting Public Q')
        qParamBytes = receiveInfo.recv(2048).decode("utf-8")
        count += 1
        if count == 10:
            raise Exception()

    global candidates
    candidates.extend(candidateNames.split("||"))
    candidates[:] = [x for x in candidates if x != ""]

    receiveInfo.close()
    return pParamBytes, gParamBytes, qParamBytes, publicKey

def sendVotes(encryptedmessages):
    count = 0
    while True:
        msgCode = connection.recv(1024).decode("utf-8")
        if msgCode == "Vote has been tampered":
            print("Invalid")
            break
        elif "You have already voted" in msgCode:
            print(msgCode)
            break
        elif "Vote is valid":
            print("Thank you for your vote!")
            break
        server.send(encryptedVotes)
        count += 1
        if count == 10:
            raise Exception()
    server.close()

def sendCommitment(secret,encryptedmessages):
    server = startSocket(2)
    count = 0

    while True:
        if server.recv(1024).decode("utf-8") == "Connection is secure":
            print("Secure")
            server.sendall(secret)
        if server.recv(1024).decode("utf-8") == "Commitment received!":
            print("Sent")
            server.sendall(encryptedmessages)
            break
        count += 1
        if count == 10:
            raise Exception()
    while True:
        msgCode = server.recv(1024).decode("utf-8")
        if msgCode == "Vote is valid!":
            print("Thank you for your vote!")
            break
        elif msgCode == "Vote is tampered!":
            print("Invalid")
            exit

def encrypt(message, p, g, public_key):
    k = number.getRandomRange(2, p-2)
    a = pow(g, k, p)
    b = (message * pow(public_key, k, p)) % p
    return a, b

def main():
    global pParamBytes, gParamBytes, qParamBytes, publicKey
    server = startSocket(1)
    pParamBytes, gParamBytes, qParamBytes, publicKey = retrieveServerInformation(server)
    votePage.run()

@votePage.route('/')
def vote_page():
    return render_template('vote.html', candidates=candidates, votingEnd=votingEnd)

@votePage.route('/vote', methods=['POST'])
def process_vote():
    global vote_list
    encrypted_vote = ""
    secret = ""
    vote = request.form['vote']
    #format candidate selection to numbers
    vote_str = '0' * len(candidates) # initializing the string with 0's
    candidate_index = int(vote) - 1 # getting the selected candidate
    vote_str = vote_str[:candidate_index] + '1' + vote_str[candidate_index + 1:] # setting the selected candidate to 1

    #convert each string in vote_list to int
    vote_list_bytes = [bytes(x, "utf-8") for x in vote_str]

    #call the encrypt function for each vote result in the vote list
    for vote in range(len(vote_list_bytes)):
        a, b = encrypt(int.from_bytes(vote_list_bytes[vote], byteorder="big"), int(pParamBytes), int(gParamBytes), int(publicKey))
        encrypted_vote = encrypted_vote + str(a) + "||" + str(b) + "***"

        ## Generate Commitment for the server to validate that the votes are not tampered with
        r = generate_r(int(qParamBytes))
        secret = secret + str(pow(int(gParamBytes),(a+b),int(pParamBytes)) * pow((a+b), r, int(pParamBytes)) % int(pParamBytes)) + "||" + str(r) + "***"

    encrypted_vote = str.encode(encrypted_vote)
    secret = str.encode(secret)
    sendCommitment(secret, encrypted_vote)
    return render_template("voteResult.html",  candidate_index=candidate_index, candidates=candidates, vote_str=vote_str)

if __name__ == "__main__":
    main()


