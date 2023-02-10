import socket

server_address = ('127.0.0.1',7777)
auth2_address = ('127.0.0.3',2345)

def retrievePublicKeys(receivePubKeyInfo):
    receivePubKeyInfo.connect(server_address)
    q = ""

    while not q:
        receivePubKeyInfo.sendall(b'Retrieve public key parameters')
        q = receivePubKeyInfo.recv(8192*10).decode("utf-8")

    ## Generate part of private key here (g^x mod p)
    partialPrivateKey = number.getRandomRange(2,q-2)
    ## Commitmenent
def main():
    auth2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth2.bind(auth2_address)

    try:
        retrievePublicKeys(auth2)
    except:
        print("Server is not up!")

if __name__ == "__main__":
    main()

