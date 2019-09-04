#!/usr/bin/python3

import pyAesCrypt
import getpass
import argparse
import sys
import os


# overwrite file and wipe it
def secure_wipe(path, passes=1):
  with open(path, "ba+") as delfile:
    length = delfile.tell()
    for i in range(passes):
      delfile.seek(0)
      delfile.write(os.urandom(length))
  os.remove(path)


# en/decrypt buffer size - 64k
buffer_size = 64 * 1024


def encrypt(password, filename):
  print("[+] Encrypting...")
  path = filename
  with open(path, "rb") as orig:
    with open(path + ".aes", "wb") as orig_enc:
      pyAesCrypt.encryptStream(orig, orig_enc, password, buffer_size)
  secure_wipe(path)


def decrypt(password, filename):
  print("[+] Decrypting...")
  enc_file_size = os.stat(filename).st_size
  # be sure the output doesn't already exist, so that you don't overwrite it
  try:
    check_file = open(filename.replace(".aes", ""), "r")
    if not check_file:
      print("This action would overwrite a file that already exists.")
  except FileNotFoundError:
    with open(filename, "rb") as enc:
      with open(filename.replace(".aes", "", 1), "wb") as dec:
        try:
          pyAesCrypt.decryptStream(enc, dec, password, buffer_size, enc_file_size)
        except ValueError:
          enc.close()
          dec.close()
          secure_wipe(filename.replace(".ase", ""))
          print("Error: Password not valid.")
          sys.exit()
    secure_wipe(filename)


def main():
  parser = argparse.ArgumentParser(add_help=False)
  parser.add_argument("-h", "--help", action='help', default=argparse.SUPPRESS, help="Show this help message and exit.")
  parser.add_argument("-e", "--encrypt", help="encrypt a file such as: -e file", required=False)
  parser.add_argument("-d", "--decrypt", help="decrypt a file such as: -e file", required=False)
  args = parser.parse_known_args(['-h', '--help', '-e', '--encrypt', '-d', '--decrypt'])
  if len(vars(args)) < 3:
    print(parser.print_help())
    sys.exit()

  try:
    password = getpass.getpass()
  except Exception as error:
    print('error', error)
  if args.e:
    print('Enter password again to confirm.')
    try:
      password2 = getpass.getpass()
    except Exception as error:
      print('error', error)
    if not password == password2:
      print('Passwords did not match.')
      sys.exit()
    else:
      filename = args.e
      encrypt(password, filename)
  if args.d:
    filename = args.d
    if filename.endswith(".aes"):
      decrypt(password, filename)
    else:
      print("Make sure the file you are decrypting ends with a .aes extension.")


if __name__ == "__main__":
  main()
