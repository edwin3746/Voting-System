from flask import Flask, redirect, url_for, render_template, request, jsonify, flash
import hashlib
import secrets
import socket
import time

## Pip install tinyec

server_address = ('127.0.0.1', 7777)
votePage = Flask(__name__)
candidates = []
votingEnd = ""

def retrieveServerInformation():
    receiveInfo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiveInfo.connect(server_address)
    publicKey_x = ""
    publicKey_y = ""
    global votingEnd
    candidateNames = ""

    while not publicKey_x and not publicKey_y:
        receiveInfo.send(b'Requesting Public Key')
        publicKey = receiveInfo.recv(8192).decode("utf-8")
        publicKey_x = publicKey.split("||")[0]
        publicKey_y = publicKey.split("||")[1]

    while not votingEnd:
        receiveInfo.send(b'Requesting Voting Deadline')
        votingEnd = receiveInfo.recv(2048).decode("utf-8")

    while not candidateNames:
        receiveInfo.send(b'Requesting Candidate Names')
        candidateNames = receiveInfo.recv(2048).decode("utf-8")

    global candidates
    candidates.extend(candidateNames.split("||"))
    candidates[:] = [x for x in candidates if x != ""]

    print(publicKey_x)
    print(publicKey_y)
    print(candidates)
    print(votingEnd)
    receiveInfo.close()

def main():
    retrieveServerInformation()
    votePage.run()

@votePage.route('/')
def vote_page():    
    return render_template('vote.html', candidates=candidates, votingEnd=votingEnd)

@votePage.route('/vote', methods=['POST'])
def process_vote():
    vote = int(request.form['vote'])
    # you can process the vote here, for example by saving it to a database

    return "Thank you for your vote"

if __name__ == "__main__":
    main()
