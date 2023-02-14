from flask import Flask, redirect, url_for, render_template, request, jsonify, flash
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes
import hashlib
import secrets
import socket
import time

## Pip install tinyec

server_address = ('127.0.0.1', 7777)
votePage = Flask(__name__)
candidates = []
votingEnd = ""
pParamBytes = ""
gParamBytes = ""
vote_str = ""
publicKey = ""

def startServer():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect(server_address)
    return server


def retrieveServerInformation(receiveInfo):
    global publicKey
    global votingEnd
    global pParamBytes
    global gParamBytes
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

    global candidates
    candidates.extend(candidateNames.split("||"))
    candidates[:] = [x for x in candidates if x != ""]

    print(candidates)
    print(votingEnd)
    receiveInfo.close()
    return pParamBytes, gParamBytes, publicKey

def sendVotes(server, encryptedVotes):
    server.send(encryptedVotes)
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


def encrypt(message, p, g, public_key):
    k = number.getRandomRange(2, p-2)
    a = pow(g, k, p)
    b = (message * pow(public_key, k, p)) % p
    return a, b


def main():
    global pParamBytes, gParamBytes, publicKey
    server = startServer()
    pParamBytes, gParamBytes, publicKey = retrieveServerInformation(server)
    votePage.run()

@votePage.route('/')
def vote_page():
    return render_template('vote.html', candidates=candidates, votingEnd=votingEnd)

@votePage.route('/vote', methods=['POST'])
def process_vote():
    global vote_list
    vote = request.form['vote']

    #format candidate selection to numbers
    vote_str = '0' * len(candidates) # initializing the string with 0's
    candidate_index = int(vote) - 1 # getting the selected candidate
    vote_str = vote_str[:candidate_index] + '1' + vote_str[candidate_index + 1:] # setting the selected candidate to 1

    #convert each string in vote_list to int
    vote_list_bytes = [bytes(x, "utf-8") for x in vote_str]
    print(vote_list_bytes)

    #call the encrypt function for each vote result in the vote list
    encrypted_vote = []
    for vote in range(len(vote_list_bytes)):
        print("Round ",vote)
        print(vote_list_bytes[vote])
        a, b = encrypt(int.from_bytes(vote_list_bytes[vote]), int(pParamBytes), int(gParamBytes), int(publicKey))
        voteConcat = a + '|' + b
        encrypted_vote.append(voteConcat + "||")
    print(encrypted_vote)

    try:
        sendVotes(encrypted_vote)
    except:
        print("An error has occured")

    return render_template("voteResult.html",  candidate_index=candidate_index, candidates=candidates, vote_str=vote_str)



if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
