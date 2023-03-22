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
import jwt

## Pip install pycryptodomex
## pip install pyJWT

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


## Define params for JWT & generate token with payload and secret key to simulate the different voters
## Assume that each voter will have a unique ID when register and server have a record of the unique ID
randomID = number.getRandomRange(1,10)
params = {'ID':randomID}
token = jwt.encode(params, 'sEcUrEkEy', algorithm='HS256')
token = str.encode(token)

def startSocket(i):
    client_address = ('127.0.0.'+str(randomIP), randomPort)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(client_address)

    serverTLS = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    serverTLS.load_verify_locations(cafile="server.crt")

    server = serverTLS.wrap_socket(server, server_hostname="GodVote")

    if i == 1:
        server.connect(server_address)
    elif i == 2:
        server.connect(receiveVote_address)
    return server

def generate_r(q):
    r = number.getRandomRange(1, q - 1)
    return r

def retrieveServerInformation(receiveInfo):
    global publicKey
    global votingEnd
    global pParamBytes
    global gParamBytes
    global qParamBytes
    candidateNames = ""
    count = 0
    verified = False

    ## Sending token to server to verify
    while not verified:
        receiveInfo.send(token)
        while True:
            msgCode = receiveInfo.recv(1024).decode("utf-8")
            if msgCode == "Valid user!":
                verified = True
                break
            else:
                raise Exception()

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

def sendVote(encryptedmessages):
    server = startSocket(2)
    count = 0
    verified = False

    msgCode = server.recv(1024).decode('utf-8')
    if  msgCode == "Receiving Vote":
        ## Sending token to server to verify
        while not verified:
            server.send(token)
            while True:
                msgCode = server.recv(1024).decode("utf-8")
                if msgCode == "Valid user!":
                    verified = True
                    server.sendall(encryptedmessages)
                    break
                else:
                    raise Exception()
        while True:
            msgCode = server.recv(1024).decode("utf-8")
            if msgCode == "Vote received!":
                print("Thank you for your vote!")
                server.close()
                break
            else:
                raise Exception()
    else:
        print(msgCode)
        exit()

def encrypt(message, p, g, q, public_key):
    r = number.getRandomRange(1, q-1)
    a = pow(g, r, p)
    b = (pow(g,(message-48),p) * pow(public_key, r, p)) % p
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
        a, b = encrypt(int.from_bytes(vote_list_bytes[vote], byteorder="big"), int(pParamBytes), int(gParamBytes), int(qParamBytes),int(publicKey))
        encrypted_vote = encrypted_vote + str(a) + "||" + str(b) + "***"

    encrypted_vote = str.encode(encrypted_vote)
    sendVote(encrypted_vote)
    return render_template("voteResult.html",  candidate_index=candidate_index, candidates=candidates, vote_str=vote_str)

if __name__ == "__main__":
    main()
