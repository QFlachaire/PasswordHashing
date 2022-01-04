import tink
import bcrypt
from tink import daead
from os import urandom, remove, path

associated_data = b"ouoo"
daead.register()
keyset_handle = tink.new_keyset_handle(
    daead.deterministic_aead_key_templates.AES256_SIV
)
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)


def check_password(user_to_check, passwd_to_check):
    # read from database
    with open("users.txt", "r") as userf, open("pwds.txt", "r") as pwdf:
        for pwdSalt, user in zip(pwdf.readlines(), userf.readlines()):
            pwd, salt = pwdSalt.split(",")
            user = user[:-1]
            if user == user_to_check:
                salt = bytes.fromhex(salt[:-1])
                hashPwd_to_check = hash_password(passwd_to_check, salt)[0]
                encrHash_to_check = encryption_machine(hashPwd_to_check).hex()
                return encrHash_to_check == pwd
        return False


def save_to_database(user, pwd):
    # use a file as a database
    # format: user, hashed_password
    with open("users.txt", "r") as file:
        for line in file.readlines():
            if line.split(",")[0] == user:
                print("User already in db")
                return False
    hashPwd, salt = hash_password(pwd)
    encrHash = encryption_machine(hashPwd)
    with open("pwds.txt", "a") as file:
        file.write(f"{encrHash.hex()},{salt.hex()}\n")
    with open("users.txt", "a") as file:
        file.write(f"{user}\n")
    return True


def encryption_machine(hash):
    plaintext = hash
    ciphertext = daead_primitive.encrypt_deterministically(plaintext, associated_data)
    return ciphertext


def hash_password(pwd, salt=None):
    if salt:
        hash = bcrypt.hashpw(pwd.encode(), salt)
    else:
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(pwd.encode(), salt)
    return hash, salt


if __name__ == "__main__":

    file = open("pwds.txt", "w")
    file.close()
    file = open("users.txt", "w")
    file.close()

    saved = save_to_database("hopla8", "totzzo")
    saved = save_to_database("hopla9", "totzzo")
    saved = save_to_database("hopla10", "totzzo")
    saved = save_to_database("hopla1", "totzzo")
    saved = save_to_database("hopla2", "totzzo")
    saved = save_to_database("hopla3", "totzzo")

    res = check_password("hopla8", "totzzo")
    print(res)