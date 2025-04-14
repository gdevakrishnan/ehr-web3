# Fernet module is imported from the 
# cryptography package 
from cryptography.fernet import Fernet 

# key is generated 
key = Fernet.generate_key() 

# value of key is assigned to a variable 
f = Fernet(key) 

data = "deva"
# the plaintext is converted to ciphertext 
token1 = f.encrypt(data.encode("utf-8"))
token2 = f.encrypt(data.encode("utf-8"))

# display the ciphertext 
print(token1) 
print(token2) 

# decrypting the ciphertext 
d = f.decrypt(token1).decode('utf-8')
print(d) 
d = f.decrypt(token2).decode('utf-8')

# display the plaintext 
print(d) 
