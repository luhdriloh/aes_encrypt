import os
import struct
import random

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def encrypt(key, infile, chunksize=1024 * 64):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The key or the password used to encrypt MUST be
            16, 24 or 32 bytes

        in_filename:
            Name of the input file to encrypt

        hunksize:
            sets the size of the chunk which the function
            uses to read and encrypt or decrypt the file.
    """

    # create a temporary out file with .enc extension
    outfile = infile + '.enc'

    # the first chunk or block of information needs something to be xor'ed
    # with which is what the initialization vector is for. it is safe to
    # be seen as long each encryption uses a differennt iv

    iv = ''

    for i in range(16):
        iv += chr(random.randint(0, 0xFF))

    # we need to hash the password so that it becomes a 32 byte value
    # we will use SHA256 to hash it then create an AES_Cipher object

    cipher_object = AES.new(key, AES.MODE_CBC, iv)

    filesize = os.path.getsize(infile)

    with open(infile, 'rb') as infile_object:
        with open(outfile, 'wb') as outfile_object:
            # write in how big the file is and the iv so that we know
            # them when we decrypt
            outfile_object.write(struct.pack('<Q', filesize))
            outfile_object.write(iv)

            while True:
                chunk = infile_object.read(chunksize)
                if len(chunk) == 0:
                    break
                    # chunks must be divisible by 16 else we pad them
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - (len(chunk) % 16))

                outfile_object.write(cipher_object.encrypt(chunk))

    os.remove(infile)


def decrypt(key, infile, chunksize=24*1024):
    """ decrypts a file using AES (CBC mode) with the
        given key. encrypts a file using AES (CBC mode) with the
        given key.

        key:
            the key or the password used to decrypt MUST be
            16, 24 or 32 bytes

        in_filename:
            name of the input file to decrypt

        chunksize:
            sets the size of the chunk which the function
            uses to read and encrypt or decrypt the file.
    """
    outfile = infile + ".temp"

    with open(infile, 'rb') as infile_object:
        # size gets the size of the file from the beginning of the
        # encrypted file. iv reads the next 16 bytes for the iv used

        size = struct.unpack('<Q', infile_object.read(struct.calcsize('Q')))[0]
        iv = infile_object.read(16)

        # we need to hash the password so that it becomes a 32 byte value
        # we will then use SHA256 to hash it thencreate an AES_Cipher object
        # like in encrypt

        cipher_object = AES.new(key, AES.MODE_CBC, iv)

        with open(outfile, 'wb') as outfile_object:
            while True:
                chunk = infile_object.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile_object.write(cipher_object.decrypt(chunk))

            outfile_object.truncate(size)

    os.remove(infile)
    os.rename(outfile, infile)


def hash_key(key):
    hash = SHA256.new(key)
    return hash.digest()
