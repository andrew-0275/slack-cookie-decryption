import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

# GLOBAL CONSTANT
SLACK_PATH_LOCAL_STATE = os.path.normpath(r"C:\Users\andre\AppData\Roaming\Slack\Local State")
SLACK_PATH = os.path.normpath(r"C:\Users\andre\AppData\Roaming\Slack")

def get_secret_key():
    try:
        # (1) Get secret key from Slack local state
        with open(SLACK_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # Remove DPAPI prefix
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(f"[ERR] Slack secret key cannot be found: {str(e)}")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_cookie(ciphertext, secret_key):
    try:
        # (3-a) Initialization vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        # (3-b) Get encrypted cookie by removing suffix bytes (last 16 bits)
        encrypted_cookie = ciphertext[15:-16]
        # (4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_cookie = decrypt_payload(cipher, encrypted_cookie)
        decrypted_cookie = decrypted_cookie.decode()
        return decrypted_cookie
    except Exception as e:
        print(f"[ERR] Unable to decrypt cookie: {str(e)}")
        return ""

def get_db_connection(slack_path_cookies_db):
    try:
        print(slack_path_cookies_db)
        shutil.copy2(slack_path_cookies_db, "CookiesVault.db")
        return sqlite3.connect("CookiesVault.db")
    except Exception as e:
        print(f"[ERR] Slack cookies database cannot be found: {str(e)}")
        return None

if __name__ == '__main__':
    try:
        with open('decrypted_cookies.csv', mode='w', newline='', encoding='utf-8') as decrypt_cookies_file:
            csv_writer = csv.writer(decrypt_cookies_file, delimiter=',')
            csv_writer.writerow(["index", "host_key", "name", "value"])
            # (1) Get secret key
            secret_key = get_secret_key()
            slack_cookies_db = os.path.normpath(r"%s\Network\Cookies" % (SLACK_PATH))
            conn = get_db_connection(slack_cookies_db)
            if secret_key and conn:
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
                for index, cookie in enumerate(cursor.fetchall()):
                    host_key = cookie[0]
                    name = cookie[1]
                    ciphertext = cookie[2]
                    if host_key and name and ciphertext:
                        # (3) Decrypt the cookie
                        decrypted_cookie = decrypt_cookie(ciphertext, secret_key)
                        print(f"Sequence: {index}")
                        print(f"Host: {host_key}\nCookie Name: {name}\nCookie Value: {decrypted_cookie}\n")
                        print("*" * 50)
                        # (5) Save into CSV
                        csv_writer.writerow([index, host_key, name, decrypted_cookie])
                # Close database connection
                cursor.close()
                conn.close()
                # Delete temp cookie db
                os.remove("CookiesVault.db")
    except Exception as e:
        print(f"[ERR] {str(e)}")
