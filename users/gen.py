#!/usr/bin/python3
import os


f = open('users/users.txt', 'r')
lines = f.readlines()
f.close()

os.makedirs("users/hashed_pw", exist_ok=True)

for line in lines:
    username, hashed_pw, _ = tuple(line.split(' '))
    with open("users/hashed_pw/" + username, 'w') as f:
        f.write(hashed_pw)
    os.makedirs("users/users/" + username, exist_ok=True)
