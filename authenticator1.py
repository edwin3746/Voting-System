import socket
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes

server_address = ('127.0.0.1',7777)
auth1_address = ('127.0.0.2',1234)

def retrievePublicKeys(receivePubKeyInfo):
    receivePubKeyInfo.connect(server_address)
    q = ""

    while not q:
        receivePubKeyInfo.sendall(b'Retrieve public key parameters')
        q = receivePubKeyInfo.recv(8192).decode("utf-8")

    receivePubKeyInfo.sendall(b"Received q")
    receivePubKeyInfo.close()

    ## Generate part of private key here (g^x mod p)
    partialPrivateKey = number.getRandomRange(2,q-2)

    ## Commitment
def main():
    auth1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth1.bind(auth1_address)
    retrievePublicKeys(auth1)
    #try:

    #except:
    #    print("Server is not up!")

if __name__ == "__main__":
    main()

