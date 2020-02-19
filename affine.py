##########################################################
## Name : Nicholas Cheung
## Title : PA Cryptography
## Class : CS 327 Discrete Structures II
## Date Due : February 19 2020
##########################################################

import sys
import numpy as np
from fractions import gcd
import time

def main():
    """ Main method to parse command line and call the functions encrypt, decrypt, or decipher. """
    if(len(sys.argv) <= 2):
        print('Invalid Number of arguments')
    action = sys.argv[1]

    # encrypt action passed
    if(action == 'encrypt'):
        if(len(sys.argv) != 6):
            raise ValueError('Invalid Number of Arguments')
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

    # decrypt action passed
    elif(action == 'decrypt'):
        if (len(sys.argv) != 6):
            raise ValueError('Invalid Number of Arguments')
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

    # decipher action passed
    elif(action == 'decipher'):
        if (len(sys.argv) != 5):
            raise ValueError('Invalid Number of Arguments')
        decipher(sys.argv[2], sys.argv[3], sys.argv[4])

    # invalid action passed
    else:
        print("Invalid Action. Please use command:\n python {encrypt, decrypt, or decipher} ...")

def extendedEuclid(a, b):
    """ Method to perform extended euclidean algorithm. """
    s = 1; t = 0; u = 0; v = 1
    while b != 0:
        q = a / b
        atemp = a
        a = b
        b = atemp % b
        stemp = s
        ttemp = t
        s = u
        t = v
        u = stemp - u * q
        v = ttemp - v * q
    return s

def encrypt(plaintext_file, output_file, a, b):
    """ Encrypts file given by plaintext_file using valid a and b values and puts it into the
    output_file. """

    encryption = ""
    with open(plaintext_file, 'r') as file:     # read file
        message = file.read()
    if(gcd(int(a), 128) != 1):      # check for valid key pair
        print("The key pair (" + a + ", " + b + ") is invalid, please select another key.")
        return
    for i in message:       # convert message
        encryption += chr((ord(i) * int(a) + int(b)) % 128)
    with open(output_file, 'w+') as file:       # write encrypted message
        file.write(encryption)
    return

def decrypt(ciphertext_file, output_file, a, b):
    """ Decrypts ciphertext_file given valid a and b keys. """
    original_message = ""
    with open(ciphertext_file, 'r') as file:        # read file
        encrypted_message = file.read()
    if(gcd(int(a), 128) != 1):      # check for valid key pair
        print("The key pair (" + a + ", " + b + ") is invalid, please select another key.")
        return

    decryption_key = extendedEuclid(int(a), 128)
    for c in encrypted_message:     # convert encrypted message
        original_message += chr(((ord(c) - int(b)) * decryption_key) % 128)
    with open(output_file, 'w+') as file: # write original message
        file.write(original_message)
    return

def decipher(ciphertext_file, output_file, dictionary_file):
    """ Brute forces through each possible a and b value, checks for number of real words 
    (given by dictionary file). Outputs decrypted message with best matches in output_file. """
    original_message = ""
    most_valid_words = 0
    valid_words_so_far = 0
    possible_a = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41,
        43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 67, 69, 71, 73, 75, 77,
        79, 81, 83, 85, 87, 89, 91, 93, 95, 97, 99, 101, 103, 105, 107, 109, 111, 113, 115,
        117, 119, 121, 123, 125]
    best_b = 1
    best_d = 1
    dict = set()
    
    with open(ciphertext_file, 'r') as file:
        encrypted_message = file.read()
    with open(dictionary_file, 'r') as file:
        for line in file:
            dict.add(line.strip())

    for a in possible_a:
        for b in range(127):
            decryption_key = extendedEuclid(a, 128)     # figure out decryption key through extended euclid
            for char in encrypted_message:
                original_message += chr(((ord(char) - b) * decryption_key) % 128)
            for word in original_message.split(' '):
                test_word = ''.join(e for e in word if e.isalnum())
                if(test_word.lower() in dict):      # check if word exists in dictionary
                    valid_words_so_far += 1
            if(valid_words_so_far > most_valid_words):
                best_b = b
                best_d = decryption_key
                most_valid_words = valid_words_so_far
            valid_words_so_far = 0
            original_message = ""
    for char in encrypted_message:
        original_message += chr(((ord(char) - best_b) * best_d) % 128)
    with open(output_file, 'w+') as file:       # write message that contains most words from dictionary
        file.write(original_message)

if __name__ == "__main__":
    main()
