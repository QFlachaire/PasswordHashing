from passwordHashing import check_password, save_to_database, hash_password, encryption_machine

from tink import daead, new_keyset_handle

associated_data = b"ouoo"
daead.register()
keyset_handle = new_keyset_handle(
    daead.deterministic_aead_key_templates.AES256_SIV
)
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)


file = open("pwds.txt", "w")
file.close()
file = open("users.txt", "w")
file.close()


while True:
    command = input("Register (R) or Login (L)?\n")
    if command not in ["R", "L"]:
        continue
    usr = input("Insert username:\n")
    pwd = input("Insert password:\n")

    if command == "R":
        if save_to_database(usr, pwd):
            print("Register successful\n")
        else: 
            print("Wrong Regsitration\n")
    elif command == "L":
        if check_password(usr, pwd):
            print("Login successful\n")
        else: 
            print("Wrong Username/Password\n")
