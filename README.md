# Project 2: Extending the JWKS server

## Description
This project uses Python to extend from Project 1. This project aims to have a functional JWKS server with RESTful API that gives public keys with expiry and unique kid to verify JWTs. These are backed by the SQLite database called ```totally_not_my_privateKeys.db```

## Sources
I used the base file for Project 1 provided by Professor Hochstetler. 
I used DeepSeek AI to complete the test suite. I imported my ```main.py``` file to the machine and prompted it to create a test suite based on the code. 

## Installation Instructions
-	Download the project folder with the LICENSE, gradebot.exe, main.py, and totally_not_my_privateKeys.db. 
-	Open a terminal.
-	Change directories to the folder. 
-	Run the main.py file by running ```python .\main.py```
-	If there are any errors, install libraries by using the command ```pip install <library_name>```
-	Rerun file with ```python .\main.py```
-	Leave this console open. The program should now be running.
-	In a separate console, change directories to the folder (where the grade bot is stored).
-	Run the grade bot using the command ```gradebot.exe project2```
-	The command should execute like the screenshot provided. 
