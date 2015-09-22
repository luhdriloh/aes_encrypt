import Encrypt

Encrypt.decrypt(Encrypt.hash_key('hello'), 'lpp.java')
# password then name of file will go above

#  if a directory use the following

# for(dirpath, dirnames, filenames) in os.walk(dir_path):
#     for file in filenames:
#         Encrypt.encrypt(hashed_password, dirpath + "/" + file)
