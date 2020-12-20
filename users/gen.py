#!/usr/bin/python3
import os


f = open('users.txt', 'r')
lines = f.readlines()
f.close()

for line in lines:
    username, hashed_pw, _ = tuple(line.split(' '))
    with open("hashed_pw/" + username, 'w') as f:
        f.write(hashed_pw)
    os.makedirs("users/" + username, exist_ok=True)
