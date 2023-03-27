# Voting-System

PEM Pass: securepassword


## Deployment Guide:

Firstly, download all the required files from github https://github.com/edwin3746/Zero-Knowledge-Voting-System. The code is written in Python, the recommended Python version to be installed on the computer will be 3.9.7. Ensure that Python is added to path variables before running the code. Ensure that the computer has Microsoft Visual C++ 14.0 or greater.
Next, run the command console and run the following 3 commands 
‘pip install pycryptodomex’ 
‘pip install pyJWT’
‘pip install pyminizip’
‘pip install pyautogui’
These four modules are required in order to run the program.
To run the program, first double click on server.py and you will be prompted with the following, enter the information as required as shown in the screenshot below.

<img width="393" alt="image" src="https://user-images.githubusercontent.com/64019173/227908578-f441e74b-f5d6-4ad2-9702-7cd843213bc1.png">

After entering the essential information, server.py will generate the parameters required and you will be prompted to enter the PEM pass phrase. The PEM pass phrase is as follows: ’securepassword’ (Do note that the characters entered will not be shown).
After entering the PEM pass phrase, a prompt will show as the screenshot below.

<img width="400" alt="image" src="https://user-images.githubusercontent.com/64019173/227908880-15c38aa0-8d76-4375-9e29-5a873b1b329c.png">

Next, run either ‘authenticator1.py’ or ‘authenticator2.py’ in sequential order. After running either of the script, the output will be as shown below indicating that Authenticator has received public parameters required. The second window is the output after running ‘Authenticator2.py’. Both scripts will return the same output.

<img width="auto" alt="image" src="https://user-images.githubusercontent.com/64019173/227909050-fddcf5fa-ebc8-42bb-a575-9ae1082e31d0.png">

After running both of the scripts, the output will be as shown in the screenshot below.

<img width="393" alt="image" src="">

Wait for the script to finish generating the required parameters and authentications. The authenticators will be prompted to enter a password to put the partial private key generated into a password protected zip file (Remember the password for the decryption process).

<img width="393" alt="image" src="">

<img width="393" alt="image" src="">

‘server.py’ will prompt you to enter the PEM pass phrase twice. A socket for sending the parameters to the voter and another socket is for receiving the votes casted by the voters. The PEM pass phrase is  ’securepassword’ (Do note that the characters entered will not be shown) for both prompts. After keying the PEM pass phrase, the output in ‘server.py’ is shown as the screenshot below.

<img width="393" alt="image" src="">

Next, run ‘client.py’ and the output is shown as the screenshot below.

<img width="393" alt="image" src="">

Open a browser and enter the link provided. Next, choose either candidate and click on ‘Submit Vote’.

<img width="393" alt="image" src="">
<img width="393" alt="image" src="">

After the voter has connected and casted the vote, the output will be shown as follows in the screenshot below on the server. 

<img width="393" alt="image" src="">

Next, you can wait for the voting period to end or close ‘client.py’ and rerun ‘client.py’ and follow the same steps to simulate multiple voters casting the vote.
After the voting period is over, ‘server.py’ will be prompted to enter the PEM pass phrase for the votes accumulation and decryption process. The PEM pass phrase is  ’securepassword’ (Do note that the characters entered will not be shown).
After keying the PEM pass phrase, let it run and finish the votes accumulation and decryption process.
Before the decryption process begins, the authenticators are prompted to enter the password for the encrypted zip file containing the private key.

‘server.py’ will have the following output as shown in the screenshot below.


<img width="393" alt="image" src="">
