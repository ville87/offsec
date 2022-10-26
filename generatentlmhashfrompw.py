import hashlib,binascii
hash = hashlib.new('md4', "password".encode('utf-16le')).digest()
print binascii.hexlify(hash)
