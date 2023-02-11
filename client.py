from flask import Flask, redirect, url_for, render_template, request, jsonify, flash
import hashlib
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
    publicKey = ""
    global votingEnd
    candidateNames = ""
    count = 0

    while not publicKey:
        receiveInfo.send(b'Requesting Public Key')
        publicKey = receiveInfo.recv(1024).decode("utf-8")
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
            
    global candidates
    candidates.extend(candidateNames.split("||"))
    candidates[:] = [x for x in candidates if x != ""]

    print(publicKey)
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
    vote = request.form['vote']
    candidate_index = int(vote) - 1
    vote_str = '0' * candidate_index + '1' + '0' * (len(candidates) - candidate_index - 1)
    return "Thank you for your vote for candidate " + candidates[candidate_index] + " with input " + vote_str

if __name__ == "__main__":
    main()
