import socket
from Cryptodome.Util import number
from Cryptodome.Random import get_random_bytes

## Pip install pycryptodomex

server_address = ('127.0.0.1',7777)
port = number.getRandomRange(1, 65536)
auth2_address = ('127.0.0.3',port)

def retrievePublicKeys(receivePubKeyInfo):
    receivePubKeyInfo.connect(server_address)
    pubKeyInfo = ""
    p = ""
    q = ""
    g = ""

    while not pubKeyInfo or not p or not q or not g:
        receivePubKeyInfo.sendall(b'Retrieve public key parameters')
        pubKeyInfo = receivePubKeyInfo.recv(8192*10).decode("utf-8")
        p = pubKeyInfo.split("||")[0]
        q = pubKeyInfo.split("||")[1]
        g = pubKeyInfo.split("||")[2]
    if p and q and g:
        receivePubKeyInfo.sendall(b"Received q")

    receivePubKeyInfo.close()

    ## Generate part of private key here (g^x mod p)
    partialPrivateKey = number.getRandomRange(2,int(q)-2)

    ## Commitmenent
def main():
    auth2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth2.bind(auth2_address)
    try:
        retrievePublicKeys(auth2)
    except:
        print("Server is not up!")
    auth2.close()

if __name__ == "__main__":
    main()

