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
import jwt
from hashlib import sha256

## Pip install pycryptodomex
## pip install pyJWT

SECRET_KEY = 'sEcUrEkEy'
server_address = ('127.0.0.1', 7777)
receiveVote_address = ('127.0.0.1', 8888)
decryptVotes_address = ('127.0.0.1', 9999)
currentPath = os.getcwd()
authConnection = []
currentVoterCon = []
votedCon = []
decryptedText = []
accumulatedVotes = {}

auth1Signature = False
auth2Signature = False

## Using JWT token to verify authenticators
def authentication(token):
    global SECRET_KEY
    try:
        verifyToken = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if verifyToken['username'] == 'authenticator1' or verifyToken['username'] == 'authenticator2':
            return True
        else:
            return False
    except:
        return False
## Using JWT token to verify voters
def authenticationVoters(token):
    global SECRET_KEY
    try:
        verifyToken = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if verifyToken['ID'] in range(1,10):
            return True
        else:
            return False
    except:
        return False

def error():
    print("Oops! Something gone wrong!")

## Establish different sockets for different purposes
## i = 1 -> General server, i = 2 -> Sockets to receive votes from voters, i = 3 -> Socket for decryption purpose
def setupServer(i):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    if i == 1:
        server_socket.bind(server_address)

    elif i == 2:
        server_socket.bind(receiveVote_address)

    elif i == 3:
        server_socket.bind(decryptVotes_address)

    server_socket.listen()
    return ssl_context, server_socket

def sendParamsToAuthenticator(publicKeyParamBytes, connection, client_address):
    while True:
        msgCode = connection.recv(1024).decode("utf-8")
        if msgCode == "Received Params!" and client_address[0] == "127.0.0.2":
            print("Authenticator 1 received Params!")
            break
        elif msgCode == "Received Params!" and client_address[0] == "127.0.0.3":
            print("Authenticator 2 received Params!")
            break
        else:
            connection.send(publicKeyParamBytes)

def syncConnectionToAuthenticator(publicKeyParamBytes):
    ## Create socket object and send public param q over
    currentConnection = []
    ssl_context, server = setupServer(1)
    auth1Count = 0
    auth2Count = 0
    connections = []
    threads = []
    stopSync = threading.Event()

    print("Waiting for Authenticator to retrieve Public Params")
    while auth1Count == 0 or auth2Count == 0:
        ## Accept all incoming conections
        connection, client_address = server.accept()
        ssl_conn = ssl_context.wrap_socket(connection,server_side=True)

        ## Ensure that only 1 from each of the IP is connected
        ## Ensure that the connection to retrieve q is only this 2 IP address
        if (client_address[0] == "127.0.0.2" or client_address[0] == "127.0.0.3") and client_address[0] not in currentConnection:
            currentConnection.append(client_address[0])
            ## Receive tokens from client to authenticate
            print(str(client_address[0]) + " has connected. Authenticating Authenticator!")
            authToken = ssl_conn.recv(2048).decode("utf-8")
            if authentication(authToken):
                ssl_conn.send(b'Valid user!')
                print(client_address[0] + " has verified. Sending Public Params to Authenticator.")
                ## Threading to send the params to and sync the Authenticators
                thread = threading.Thread(target = sendParamsToAuthenticator, args=(publicKeyParamBytes, ssl_conn, client_address))
                threads.append(thread)
                thread.start()
                connections.append(ssl_conn)
                if client_address[0] == "127.0.0.2":
                    auth1Count = 1
                elif client_address[0] == "127.0.0.3":
                    auth2Count = 1
            else:
                currentConnection.remove(client_address[0])
                print("Invalid Connections!")
                ssl_conn.sendall(b'Invalid')

            if auth1Count == 1 and auth2Count == 1:
                break
        else:
            print("Invalid Connections!")
            ssl_conn.sendall(b'Invalid')

    ## Notify the threads to stop
    stopSync.set()
    ## Send the message for the threads to continue
    for con in connections:
        con.send(b"Partial Private Key Generated Complete!")
    for thread in threads:
        thread.join()
    return ssl_context,server

def retrieveCommitmentValues(ssl_context, server):
    global currentConnection
    auth1Count = 0
    auth2Count = 0
    auth1Secret = ""
    auth2Secret = ""

    print("Waiting for Authenticator to send Commitment value")
    while auth1Count == 0 or auth2Count == 0:
        ## Accept all incoming conections
        connection, client_address = server.accept()
        ssl_con = ssl_context.wrap_socket(connection, server_side=True)

        ## Retrieve token such that to ensure that the data sent is from Authenticators
        authToken = ssl_con.recv(2048).decode("utf-8")

        ## Retrieve commitment values
        ## Ensure that both auth1 and auth2 send commitment before proceed
        if authentication(authToken):
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

    return auth1Secret,auth2Secret

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

        ## Retrieve token such that to ensure that the data sent is from Authenticators
        authToken = ssl_con.recv(2048).decode("utf-8")

        ## Retrieve partial public key from Authenticators
        if authentication(authToken):
            ssl_con.sendall(b'Connection is secure')
            msgCode = ssl_con.recv(8192).decode("utf-8")
            if client_address[0] == "127.0.0.2":
                auth1PartialPublicKey = msgCode.split("||")[0]
                auth1R = msgCode.split("||")[1]
                ## Ensure that the partial public key received matches the commitment sent earlier
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
                ## Ensure that the partial public key received matches the commitment sent earlier
                if str((pow(g,int(auth2PartialPublicKey),p) * pow(int(auth2PartialPublicKey),int(auth2R),p)) % p) == auth2Secret:
                    auth2Count = 1
                    print("Authenticator 2 partial public key is valid!")
                    ssl_con.sendall(b'Valid')
                else:
                    print("Error! Maybe someone else tried to send partial public key!")
                    ssl_con.sendall(b'Invalid')
        else:
            print("Invalid Connections!")
            ssl_con.sendall(b'Invalid')
    server.close()
    return auth1PartialPublicKey, auth2PartialPublicKey, auth1R, auth2R

def sendParamsToVoters(votingEnd,publicKeyBytes,candidateNames,pParamBytes,gParamBytes,qParamBytes,ssl_conn,stopEvent,client_address):
    try:
        while True:
            ## Retrieve token from Voters
            authToken = ssl_conn.recv(2048).decode("utf-8")
            if authenticationVoters(authToken):
                ssl_conn.sendall(b'Valid user!')
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
            else:
                ssl_conn.sendall(b'Invalid!')

    except:
        if not stopEvent.is_set():
            print("Voter with IP: " + client_address[0] + " has retrieve the information!")
        else:
            return

def socketSetupForPublic(ssl_context,server,publicKeyBytes,candidateNames,votingEnd, pParamBytes, gParamBytes, qParamBytes, stopEvent, votingEndDate):
    ## Socket will keep releasing public information to voters who connect
    # Change while True to while the time is not up yet
    global currentVoterCon
    while not stopEvent.is_set() and datetime.datetime.now() < votingEndDate:
        try:
            print("Waiting for client to retrieve Public Information")
            if server.accept():
                connection, client_address = server.accept()
                ssl_conn = ssl_context.wrap_socket(connection,server_side=True)
                print("Connection From : ", client_address)
                currentVoterCon.append(client_address)
                thread = threading.Thread(target=sendParamsToVoters, args=(votingEnd,publicKeyBytes,candidateNames,pParamBytes,gParamBytes,qParamBytes,ssl_conn,stopEvent,client_address))
                thread.start()
        except:
            return

def receiveVotesFromVoters(ssl_conn,stopEvent,g,p,client_address):
    global votedCon
    global accumulatedVotes
    try:
        authToken = ssl_conn.recv(2048).decode("utf-8")
        if authenticationVoters(authToken):
            ssl_conn.sendall(b'Valid user!')
            votersEncryptedVote = ssl_conn.recv(8192).decode("utf-8")
            encryptedVotes = votersEncryptedVote.split("***")
            votedCon.append(client_address)
            if accumulatedVotes:
                ## Assign the encrypted vote values into a dictionary
                ## Key of the dictionary will be the candidate number
                for g in range (0,len(encryptedVotes)-1):
                    oldVoteData = accumulatedVotes[g+1]
                    oldVoteData.append(encryptedVotes[g])
                    accumulatedVotes[g+1] = oldVoteData
            else:
                for g in range (0,len(encryptedVotes)-1):
                    accumulatedVotes[g+1] = [encryptedVotes[g]]
            ssl_conn.sendall(b'Vote received!')
            ssl_conn.close()
        else:
            ssl_conn.sendall(b'Invalid!')
    except:
        if not stopEvent.is_set():
            print("A voter with IP: " + client_address[0] + " has submitted a vote!")
        else:
            return

def receiveVotes(ssl_context,server,votingEnd,g,p, stopEvent, votingEndDate):
    ## Socket will keep receiving votes from voters who connect
    global currentVoterCon
    global votedCon
    # Change while True to while the time is not up yet
    while not stopEvent.is_set() and datetime.datetime.now() < votingEndDate:
        try:
            print("Waiting for votes")
            ## Accept all incoming connections
            connection, client_address = server.accept()
            ssl_conn = ssl_context.wrap_socket(connection,server_side=True)
            print("Connection From For Votes: ", client_address)
            if (client_address in currentVoterCon) and (client_address not in votedCon):
                ssl_conn.send(b'Receiving Vote')
                thread = threading.Thread(target=receiveVotesFromVoters, args=(ssl_conn,stopEvent,g,p,client_address))
                thread.start()
            else:
                ssl_conn.send(b'You have already voted. Results will be released at ' + votingEnd)
        except:
            print("Voting Period is over!")

def retrieveDecryptedVote(ssl_conn, encryptedAValue):
    global decryptedText
    ssl_conn.sendall(encryptedAValue)
    while True:
        decryptedVote = ssl_conn.recv(8192).decode("utf-8")
        decryptedVote = decryptedVote + "***"
        decryptedText.append(decryptedVote)
    return

def verifyAuthenticators(ssl_conn,privateKeySignature, p, g, publicKey, client_address, auth1Commitment, auth2Commitment, auth1R, auth2R):
    global auth1Signature
    global auth2Signature

    while True:
        ssl_conn.sendall(b"Connection is secure")
            ## Retrieve ZKP signature from authenticators
        signature = ssl_conn.recv(8192).decode("utf-8")
        authPublicKey = signature.split("||")[2]
        ## Retrieve individual value of ZKP for validating
        e = int(signature.split("||")[0])
        s = int(signature.split("||")[1])
        if client_address[0] == "127.0.0.2":
            if (str((pow(g,int(authPublicKey),p) * pow(int(authPublicKey),int(auth1R),p)) % p) == auth1Commitment):
                print("Authenticator 1 Partial Public Key is valid!")
                if verifySchnorr(p,g,s,e,int(authPublicKey),'Auth1') == True:
                    print("Authenticator 1 have valid signature!")
                    ssl_conn.send(b"Verification complete")
                    auth1Signature = True
                    break
            else:
                print("Invalid!")
        elif client_address[0] == "127.0.0.3":
            if (str((pow(g,int(authPublicKey),p) * pow(int(authPublicKey),int(auth2R),p)) % p) == auth2Commitment):
                print("Authenticator 2 Partial Public Key is valid!")
                if verifySchnorr(p,g,s,e,int(authPublicKey),'Auth2') == True:
                    print("Authenticator 2 have valid signature!")
                    ssl_conn.send(b"Verification complete")
                    auth2Signature = True
                    break
            else:
                print("Invalid!")

def decryptVote(ssl_context, verifyAuth, privateKeySignature, p, g, publicKey, accumulatedEncryptedAValue, auth1Commitment, auth2Commitment, auth1R, auth2R):
    global auth1Signature
    global auth2Signature
    connections = []
    decryptedVote = ""

    ## Validate if authenticators have the private key with ZKP
    while True:
        print("Waiting for Authenticators to send Private Key Signature!")
        connection, client_address = verifyAuth.accept()
        ssl_conn = ssl_context.wrap_socket(connection,server_side=True)

        ## Retrieve token such that to ensure that the data sent is from Authenticators
        authToken = ssl_conn.recv(2048).decode("utf-8")

        ## Retrieve partial public key from Authenticators
        if authentication(authToken):
            thread = threading.Thread(target = verifyAuthenticators, args=(ssl_conn, privateKeySignature, p, g, publicKey, client_address,auth1Commitment, auth2Commitment, auth1R, auth2R))
            thread.start()
            connections.append(ssl_conn)
        else:
            print("Invalid Connection!")
        time.sleep(5)
        if auth1Signature == True and auth2Signature == True:
            break

    print("Authenticators has been verified!")
    print("Sending encrypted A to the authenticators")
    for con in connections:
        con.send(accumulatedEncryptedAValue)
        decryptedVote = decryptedVote + con.recv(8192).decode("utf-8")

    print("Votes has been decrypted by Authenticators")
    return decryptedVote

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
def fullDecrypt(partialDecrypted1, partialDecrypted2, partialDecrypted3, p, ciphertext,g):
    # can replace ciphertext with b if you want
    b = ciphertext
    yM = (partialDecrypted1 * partialDecrypted2 * partialDecrypted3 * b) % p
    for i in range(0,2**8):
        if (pow(g,i,p)==yM):
            if i == 1 or i == 0:
                return i
            else:
                return 0
            break

# creating the Schnorr signature
def schnorrSignature(p, q, g, privateKey, message):
    messageInASCII = ''.join(str(ord(c)) for c in message)
    r = random.randint(1, q - 1)
    x = pow(g, r, p)
    e = hashThis(x, messageInASCII) % p
    s = pow((r - (privateKey * e)), 1, p - 1)
    return str(e), str(s)

# sample hash function
def hashThis(r, message):
    hash=sha256();
    hash.update(str(r).encode());
    hash.update(message.encode());
    return int(hash.hexdigest(),16)

# verification of Schnorr signature
def verifySchnorr(p, g, s, e, publicKey, message):
    messageInASCII = ''.join(str(ord(c)) for c in message)
    rv = pow(pow(g, s, p) * pow(publicKey, e, p), 1, p)
    ev = hashThis(rv, messageInASCII) % p
    return str(ev) == str(e)

def main():
    ## Retrieve the number of candidates and their names respectively
    global accumulatedVotes

    candidates = []
    candidateNames = ""
    num = ""
    name = ""
    votingHours = ""

    while True:
        num = input("Enter the number of candidates : ")
        if num.isdigit():
            break
        else:
            print("Error! Enter numbers only!")
    for loop in range(int(num)):
        while name == "":
            name = input("Enter the name of candidate " + str(loop+1) + ":" )
            candidates.append(name)
        name = ""

    for names in candidates:
        candidateNames += names + "||"

    ## Convert name to bytes
    candidateNames = str.encode(candidateNames)

    while True:
        votingHours = input ("Enter the number of hours allowed to vote : ")
        if votingHours.isdigit() and int(votingHours) > 0:
            break
        else:
            print("Error! Minimum voting hour is 1 hour!")
    ## Convert to hours and then to bytes
    votingEndDate = datetime.datetime.now() + datetime.timedelta(minutes = int(votingHours))
    votingEnd = str.encode(votingEndDate.strftime("%Y-%m-%d %H:%M:%S"))
    print("Initializing....Generating parameters")
    ## Generate the parameters using ElGamal
    p, q = generate_primes()
    g = generate_g(p, q)

    print("Parameters generated!")
    ## Convert q to bytes to be send over to Authenticator using Socket
    publicKeyParam = str(p) + "||" + str(q) + "||" + str(g) + "||"
    publicKeyParamBytes = str.encode(publicKeyParam)

    ## Step 1: Send all the params required to the respective Authenticators to generate their private and public keys
    ssl_context, server = syncConnectionToAuthenticator(publicKeyParamBytes)
    print("Partial Public Key is generated on individual Authenticator")

    ## Step 2: Retrieve the partial public key generated by Authenticators
    ## Retrieve the commitment values from Authenticators
    auth1Commitment, auth2Commitment = retrieveCommitmentValues(ssl_context,server)
    partialPublicKey1, partialPublicKey2, auth1R, auth2R = authenticatorPartialPublicKey(ssl_context,server,auth1Commitment,auth2Commitment,g,p)

    ## Step 3: Generate the partial public key
    partialPrivateKey = number.getRandomRange(1, q)
    partialPublicKey3 = pow(g,partialPrivateKey,p)

    ## Step 4: Combine the partial public key together to obtain a public key
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

    ## Step 5: Start a socket for voters to connect and retrieve the voting information
    stopPublicServer = threading.Event()
    ## Threaded socket is started for voters to receive information and send votes back to server
    try:
        ssl_context,server = setupServer(1)
    except:
        print("Invalid Authentication")
    sendInfoToVoters = threading.Thread(target = socketSetupForPublic, args=(ssl_context,server,publicKeyBytes,candidateNames,votingEnd, pParamBytes, gParamBytes, qParamBytes, stopPublicServer, votingEndDate))
    sendInfoToVoters.start()

    try:
        ssl_context1,receiveVote = setupServer(2)
    except:
        print("Invalid Authentication")
    receiveServer = threading.Thread(target = receiveVotes, args=(ssl_context1,receiveVote,votingEnd,int(gParam),int(pParam), stopPublicServer, votingEndDate))
    receiveServer.start()

    print(votingEndDate)

    ## Sleep until the time is up and server will shutdown and start to decrypt votes
    if votingEndDate < datetime.datetime.now():
        print("Voting Period is over. Please restart the server")
        time.sleep(10)
        exit()
    timeDifference = votingEndDate - datetime.datetime.now()
    timeDifferenceinSec = timeDifference.total_seconds()
    time.sleep(timeDifferenceinSec)
    stopPublicServer.set()
    server.close()
    receiveVote.close()
    sendInfoToVoters.join()
    receiveServer.join()

    print("Voting period is over. Accumulating and decrypting votes!")

    ## Votes are stored in a dictionary. Key = Candidate, value = (A,B)
    ## Extract A and B respectively
    ## A is then send to Authenticators for decryption
    accumulatedEncryptedAValue = ""
    accumulatedEncryptedBValue = ""
    partialDecryptedVote = ""
    voteResult = ""
    splitEncryptedVote = []
    aValue = 1
    bValue = 1
    count = 0
    ## If voters have casted their votes
    if accumulatedVotes:
        ## Loop through the candidates and retrieve their (a,b) values and perform homographic addition before decrypting
        for key, encryptedVotes in accumulatedVotes.items():
            for votes in accumulatedVotes[key]:
                if count == 0:
                    aValue = int(votes.split('||')[0])
                    bValue = int(votes.split('||')[1])
                else:
                    ## Homographic addition (a1*a2)%p and (b1*b2)%p
                    aValue = (aValue * int(votes.split('||')[0])) % p
                    bValue = (bValue * int(votes.split('||')[1])) % p
                count += 1
            ## Contains the ciphertexts of different candidates
            accumulatedEncryptedAValue = accumulatedEncryptedAValue + str(aValue) + "||"
            accumulatedEncryptedBValue = accumulatedEncryptedBValue + str(bValue) + "||"
            aValue = 1
            bValue = 1
            count = 0
        e, s = schnorrSignature(p, q, g, partialPrivateKey, 'Auth3')

        privateKeySignature = e + "||" + s
        privateKeySignature = str.encode(privateKeySignature)
        ## Set up socket to send A to authenticators
        try:
            ssl_context,verifyAuth = setupServer(3)
        except:
            print("Invalid Authentication")

        ## Convert ciphertext A and send to authenticators to perform partial decryption
        accumulatedEncryptedAValueByte = str.encode(accumulatedEncryptedAValue)
        ## partialPublicKey is parsed to verify that the authenticators have the valid private key using ZKP
        decryptedVote = decryptVote(ssl_context,verifyAuth, privateKeySignature, p, g, publicKey, accumulatedEncryptedAValueByte, auth1Commitment, auth2Commitment, auth1R, auth2R)
        ## Decrypt A value using server's partial private key
        splitEncryptedVote = accumulatedEncryptedAValue.split("||")
        for i in range(0, len(splitEncryptedVote)-1):
            partialDecryptedVote = partialDecryptedVote + str(partialDecrypt(int(splitEncryptedVote[i]), partialPrivateKey, p)) + "||"
        ## Decrypt to retrieve the results, Data parsed into fullDecrypt -> (partialDecryptAValue by Auth1, partialDecryptAValue by Auth2, partialDecryptAValue by Server, p, B value)
        a = 0
        b = int((len(decryptedVote.split("||"))-1) / 2)
        for j in range(0, len(splitEncryptedVote)-1):
            voteResult = voteResult + str(fullDecrypt(int(decryptedVote.split("||")[a]), int(decryptedVote.split("||")[b]), int(partialDecryptedVote.split("||")[j]), p, int(accumulatedEncryptedBValue.split("||")[j]),g)) + "|"
            a += 1
            b += 1
    else:
        voteResult = "No one voted!"

    print("Voting Results!: ")
    print(voteResult)
    time.sleep(1000)

if __name__ == "__main__":
    main()



