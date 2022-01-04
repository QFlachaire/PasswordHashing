# PasswordHashing - M1 ESILV FinTech
Project from the Symmetric Cryptography Course I followed in 2021 during my Master at ESILV in Fintech.

## Introduction
The point here is to create a registration tool which securely store users passwords.

the threats are:
- Mass password cracking. The attacker wants to crack as many passwords as possible.
- Targeted password cracking. The attacker wants to crack only a handful of passwords.
- Database breaches. The attacker obtains a database containing (hash of) user passwords.

## Implementation
```
database = 'database.txt'
secret_key = 'xxx' # use Tink to generate your secret key here

def hash_password(pwd):
  # implement your scheme
  return hash

def encryption_machine(msg):
  # encrypt using AES-SIV
  return ciphertext

def save_to_database(user, pwd):
  # use a file as a database
  # format: user, hashed_password
  # for example: file.write(user, hash_password(pwd))

def check_password(user, pwd):
  # read from database
  # and check for authentication
  return false/true
```

Please execute main.py to test the program.
