# README

## Author
Vijay Anirudh Aithi


## Submitted Source Files
- dwork.c
- encryption.c
- decryption.c
- network_utils.c
- README.md



## Run these commands

    ##for Network mode encryption
    ./purenc testfile -d 127.0.0.1:8080

    ##for Local mode encryption
    ./purenc 1cnn.pdf -l

    ##for Local mode decryption
    ./purdec -l 1cnn.pdf.pur

    ##for Network mode decryption
    ./purdec 8080



## Description of Code and Code Layout
The project consists of several source files:
- `purenc.c`: Main program logic contains functions for file encryption, including key derivation, encryption, and HMAC computation.Also for handling command-line arguments and controlling the encryption for local and network file processing - consists two encrypt file functions one for local and other for network.

- `purdec.c`: Contains functions for file decryption, including key derivation, decryption, and HMAC verification. Also for handling command-line arguments and controlling the encryption for local and network file processing - consists two encrypt file functions one for local and other for network.

- `README.md`: This file.

The code follows a modular structure, with each source file responsible for a specific aspect of the functionality. Functions are appropriately named and organized to enhance readability and maintainability.

## General Comments and Design Decisions
- The project uses PBKDF2 for key derivation to ensure strong key generation based on user passwords. The iteration count and salt value are chosen to increase the computational cost and improve security against brute-force attacks.
- AES256 encryption is used for secure data encryption, providing strong cryptographic protection for sensitive information.
- Network communication is implemented using TCP for reliable data transmission between client and server.
- Error handling and input validation are incorporated throughout the code to enhance robustness and prevent unexpected behavior.

## Dealing with PBKDF2
PBKDF2 (Password-Based Key Derivation Function 2) requires extra input, including the password, salt, iteration count, and desired key length. It is used to derive a cryptographic key from a password.

In our program, PBKDF2 is utilized to compute the key for encryption and decryption. The user provides a password, which is combined with a salt value to generate a secure key. The iteration count determines the number of iterations the function goes through to derive the key, making it computationally intensive and resistant to brute-force attacks.

## Number of Hours Spent and Level of Effort
I spent approximately 20 hours on this project, with a medium level of effort. The majority of the time was dedicated to implementing encryption/decryption logic, handling network communication, and testing the functionality to ensure reliability and security.


