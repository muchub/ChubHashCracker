#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Chub Hash Cracker
Author: Muchub (https://github.com/muchub/)
Description: A Python script to crack MD5, SHA1 and Bcrypt hashes.
Usage: python3 chub.py
"""

from colorama import Fore, Style
import threading
import time
import hashlib
import sys
import bcrypt
import os

def chub_ascii():
    os.system('cls')  
    print(Fore.GREEN + """
             /\_/\\  """ + Fore.RED + "Chub Hash Cracker !" + Fore.GREEN + """
            ( o.o ) """ + Fore.BLUE + "Crack your hash !" + Fore.GREEN + """
             > ^ < """ + Fore.BLUE + " Author - " + Fore.GREEN + "Muchub" + Fore.GREEN + """
        """ + Style.RESET_ALL)

def loading_spinner():
    while not crack_done.is_set():
        for char in '|/-\\':
            print(f'\r{Fore.BLUE}Cracking {hash_type[int(opt) - 1]} {Fore.RED}{hash} {Fore.BLUE} {char} {Style.RESET_ALL}', end='', flush=True)
            time.sleep(0.1)
            if crack_done.is_set():
                sys.exit()

def binary_count(lst):
    carry = 1
    for i in range(len(lst) - 1, -1, -1):
        lst[i] += carry
        carry = lst[i] // len(chars)
        lst[i] %= len(chars)
    return lst

def chub_md5(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()

def chub_sha1(input_string):
    sha1_hash = hashlib.sha1(input_string.encode()).hexdigest()
    return sha1_hash

def chub_bcrypt(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def chub_guess(hash, start, end, hash_t, min_length):
    chub_ascii()
    print(f"Testing in minimum character : {min_length}")
    for length in range(min_length, end):
        binary_list = [0] * length
        while True:
            combination = ''.join([chars[i] for i in binary_list])
            hash_x = ""
            if hash_t == 1:
                hash_x = chub_md5(combination)
            if hash_t == 2:
                hash_x = chub_sha1(combination)
            if hash_t == 3:
                if chub_bcrypt(combination, hash): 
                    hash_x = hash
                
            if hash_x == hash:
                end_time = time.time()
                print(f"\n\n{Fore.GREEN}[+]\tHash found in {end_time - start_time:.2f} seconds !\t[+]\n\n{Fore.WHITE}Hash: {hash}\nType: {hash_type[hash_t - 1]} \nResult: {Fore.GREEN}{combination} {Style.RESET_ALL}\n")
                crack_done.set()
                sys.exit()
            if binary_list.count(len(chars) - 1) == length:
                break
            binary_list = binary_count(binary_list)
    print(f"\n{Fore.RED}[-]\tNo result found.\t[-]{Style.RESET_ALL}")
    sys.exit()

chars = [chr(i) for i in range(ord('a'), ord('z')+1)] + \
        [chr(i) for i in range(ord('A'), ord('Z')+1)] + \
        [chr(i) for i in range(ord('0'), ord('9')+1)] + \
        ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', ';', ':', ',', '.', '<', '>', '/', '?', '|', '\\', '~', '`']

hash_type = ['md5', 'sha1', 'bcrypt']

chub_ascii()
print("1. MD5\n2. SHA1\n3. Bcrypt\n")
opt = input("Enter Option: ")
chub_ascii()
hash = input(f"\nEnter {hash_type[int(opt) - 1]} hash: ")
min_length = int(input("Enter possible minimum character length: "))  # Set minimum character length

start_time = time.time()
crack_done = threading.Event()
num_threads = 1
chunk_size = len(chars) // num_threads
threads = []
for i in range(num_threads):
    start = i * chunk_size
    end = (i + 1) * chunk_size if i < num_threads - 1 else len(chars)
    t = threading.Thread(target=chub_guess, args=(hash, start, end, int(opt), min_length))  # Pass min_length
    threads.append(t)

loading_thread = threading.Thread(target=loading_spinner)
loading_thread.start()

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()

loading_thread.join()
