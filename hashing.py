import hashlib

#password to be hashed
password = "password"

#Encode the password to base64
encoded_password = password.encode()

#MD hashing
#MD5 is pretty obsolete now, and you should never use it, as it isn't collision-resistant
md5 = hashlib.md5(encoded_password).hexdigest()
print("MD5 Hash: ",md5)

#SHA1 hashing
sha1 = hashlib.sha1(encoded_password).hexdigest()
print("SHA1 Hash: ",sha1)

# hash with SHA-2 (SHA-224, SHA-256, SHA-384 and SHA-512)
#The reason it's called SHA-2 (Secure Hash Algorithm 2), is because SHA-2 is the successor of SHA-1, which is outdated and easy to break, the motivation of SHA-2 was to generate longer hashes which leads to higher security levels than SHA-1
#Although SHA-2 is still used nowadays, many believe that attacks on SHA-2 are just a matter of time; researchers are concerned about its long-term security due to its similarity to SHA-1.
#sha224 hashing
sha224 = hashlib.sha224(encoded_password).hexdigest()
print("SHA224 Hash: ",sha224)

#sha256 hashing
sha256 = hashlib.sha256(encoded_password).hexdigest()
print("sha256 Hash: ",sha256)

#sha384 hashing
sha384 = hashlib.sha384(encoded_password).hexdigest()
print("sha384 Hash: ",sha384)

#sha384 hashing
sha384 = hashlib.sha384(encoded_password).hexdigest()
print("sha384 Hash: ",sha384)

#As a result, SHA-3 is introduced by NIST as a backup plan, which is a sponge function that is completely different from SHA-2 and SHA-1. Let's see it in Python:
#SHA-3 is unlikely to be broken any time soon. In fact, hundreds of skilled cryptanalysts have failed to break SHA-3.
#There are few incentives to upgrade to SHA-3, since SHA-2 is still secure, and because speed is also a concern, SHA-3 isn't faster than SHA-2.
#sha3_224 hashing
sha3_224 = hashlib.sha3_224(encoded_password).hexdigest()
print("sha3_224 Hash: ",sha3_224)

#sha3_256 hashing
sha3_256 = hashlib.sha3_256(encoded_password).hexdigest()
print("sha3_256 Hash: ",sha3_256)

#sha3_384 hashing
sha3_384 = hashlib.sha3_384(encoded_password).hexdigest()
print("sha3_384 Hash: ",sha3_384)

#sha3_512 hashing
sha3_512 = hashlib.sha3_512(encoded_password).hexdigest()
print("sha3_512 Hash: ",sha3_512)

#What if we want to use a faster hash function that is more secure than SHA-2 and at least as secure as SHA-3 ? The answer lies in BLAKE2:
#BLAKE2 hashes are faster than SHA-1, SHA-2, SHA-3, and even MD5, and even more secure than SHA-2. It is suited for use on modern CPUs that support parallel computing on multicore systems.
# hash with BLAKE2
# 256-bit BLAKE2 (or BLAKE2s)
blake2s = hashlib.blake2s(encoded_password).hexdigest()
print("BLAKE2c:", blake2s)

# 512-bit BLAKE2 (or BLAKE2b)
blake2b = hashlib.blake2b(encoded_password).hexdigest()
print("BLAKE2b:", blake2b)

#Hashing a file
file = ".\myfile.txt" # Location of the file (can be set a different way)
BLOCK_SIZE = 65536 # The size of each read from the file

file_hash = hashlib.sha256() # Create the hash object, can use something other than `.sha256()` if you wish
with open(file, 'rb') as f: # Open the file to read it's bytes
    fb = f.read(BLOCK_SIZE) # Read from the file. Take in the amount declared above
    while len(fb) > 0: # While there is still data being read from the file
        file_hash.update(fb) # Update the hash
        fb = f.read(BLOCK_SIZE) # Read the next block from the file

print ("File hash: ",file_hash.hexdigest()) # Get the hexadecimal digest of the ha

#What do we mean by secure in hashing algorithms? Hashing functions have many safety characteristics, including collision resistance, which is provided by algorithms that make it extremely hard for an attacker to find two completely different messages that hash to the same hash value.

#Pre-image resistance is also a key factor for hash algorithm security. An algorithm that is pre-image resistant makes it hard and time-consuming for an attacker to find the original message given the hash value.