import socket
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes

## Pip install pycryptodomex

server_address = ('127.0.0.1',7777)
port = number.getRandomRange(1, 65536)
auth1_address = ('127.0.0.2',port)

def retrievePublicKeys(receivePubKeyInfo):
    receivePubKeyInfo.connect(server_address)
    pubKeyInfo = ""
    p = ""
    q = ""
    g = ""

    while not pubKeyInfo or not p or not q or not g:
        receivePubKeyInfo.send(b'Retrieve public key parameters')
        pubKeyInfo = receivePubKeyInfo.recv(8192*10).decode("utf-8")
        p = pubKeyInfo.split("||")[0]
        q = pubKeyInfo.split("||")[1]
        g = pubKeyInfo.split("||")[2]
    if p and q and g:
        receivePubKeyInfo.send(b"Received q")

    receivePubKeyInfo.close()

    ## Generate part of private key here (g^x mod p)
    partialPrivateKey = number.getRandomRange(2,int(q)-2)

    ## Commitment
def main():
    auth1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    auth1.bind(auth1_address)
    try:
        retrievePublicKeys(auth1)
    except:
        print("Server is not up!")
    auth1.close()

if __name__ == "__main__":
    main()


