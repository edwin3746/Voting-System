# God's Vote

PEM Pass: securepassword


## Deployment Guide:

Firstly, download all the required files from github https://github.com/edwin3746/Zero-Knowledge-Voting-System. The code is written in Python, the recommended Python version to be installed on the computer will be 3.9.7. Ensure that Python is added to path variables before running the code. Ensure that the computer has Microsoft Visual C++ 14.0 or greater.
Next, run the command console and run the following commands 
1. ‘pip install pycryptodomex’ 
2. ‘pip install pyJWT’
3. ‘pip install pyminizip’
4. ‘pip install pyautogui’

These four modules are required in order to run the program.
To run the program, first double click on server.py and you will be prompted with the following, enter the information as required as shown in the screenshot below.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227908578-f441e74b-f5d6-4ad2-9702-7cd843213bc1.png">

After entering the essential information, server.py will generate the parameters required and you will be prompted to enter the PEM pass phrase. The PEM pass phrase is as follows: ’securepassword’ (Do note that the characters entered will not be shown).
After entering the PEM pass phrase, a prompt will show as the screenshot below.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227908880-15c38aa0-8d76-4375-9e29-5a873b1b329c.png">

Next, run either ‘authenticator1.py’ or ‘authenticator2.py’ in sequential order. After running either of the script, the output will be as shown below indicating that Authenticator has received public parameters required. The second window is the output after running ‘Authenticator2.py’. Both scripts will return the same output.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227909755-15d56001-ac43-4e7f-97c2-e9de4b1ca6c5.png">

After running both of the scripts, the output will be as shown in the screenshot below.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227909050-fddcf5fa-ebc8-42bb-a575-9ae1082e31d0.png">

Wait for the script to finish generating the required parameters and authentications. The authenticators will be prompted to enter a password to put the partial private key generated into a password protected zip file (Remember the password for the decryption process).

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227909898-4d2889cb-6f49-4127-8f42-eedbcb5c8be6.png">

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227909971-ff4e0ece-3c1e-49e2-a7ac-bcee657940d3.png">

‘server.py’ will prompt you to enter the PEM pass phrase twice. A socket for sending the parameters to the voter and another socket is for receiving the votes casted by the voters. The PEM pass phrase is  ’securepassword’ (Do note that the characters entered will not be shown) for both prompts. After keying the PEM pass phrase, the output in ‘server.py’ is shown as the screenshot below.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227910042-fa79835f-37f6-4e2a-994d-fef4211c1cd2.png">

Next, run ‘client.py’ and the output is shown as the screenshot below.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227910209-58101f02-b82d-4b19-91b0-51392cef54a3.png">

Open a browser and enter the link provided. Next, choose either candidate and click on ‘Submit Vote’.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227910401-e9f8182f-bdb8-4ed8-a271-06cb70505d76.png">

After the voter has connected and casted the vote, the output will be shown as follows in the screenshot below on the server. 

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227910511-7ac32b27-db94-49fd-8879-65ba19782953.png">

Next, you can wait for the voting period to end or close ‘client.py’ and rerun ‘client.py’ and follow the same steps to simulate multiple voters casting the vote.
After the voting period is over, ‘server.py’ will be prompted to enter the PEM pass phrase for the votes accumulation and decryption process. The PEM pass phrase is  ’securepassword’ (Do note that the characters entered will not be shown).
After keying the PEM pass phrase, let it run and finish the votes accumulation and decryption process.
Before the decryption process begins, the authenticators are prompted to enter the password for the encrypted zip file containing the private key.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227910662-ac3e7910-089d-4e20-ba8c-b9f52daaade7.png">
<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227910667-efffe00a-a883-4196-857e-e6953c2f5eee.png">

‘server.py’ will have the following output as shown in the screenshot below.



