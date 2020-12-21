#!/usr/bin/python3

import subprocess
import string
import random

def step(description):
    print("========================================================================")
    print(description)
    print("========================================================================")

def run(cmd):
    a = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    #print(a)
    return a

def get_radom_string(arg_len_left=1, arg_len_right=100):
    arg_len = random.randint(arg_len_left, arg_len_right)
    letters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(letters) for i in range(arg_len))

def get_random_cmd(li, arg_num_left=2, arg_num_right=5):
    arg_num = random.randint(arg_num_left, arg_num_right)
    for _ in range(arg_num):
        li.append(get_radom_string())
    return " ".join(li)

if __name__ == "__main__":
    step("Users cannot getcert with wrong username/password pair.")
    for _ in range(10):
        assert run(get_random_cmd(["./getcert.out"])).returncode == 1
    for _ in range(10):
        assert run("./getcert.out addleness " + get_radom_string()).returncode == 1
    
    step("Users can getcert with correct username/password pair.")
    assert run("./getcert.out addleness Cardin_pwns").returncode == 0
    assert run("./getcert.out overrich Freemasonry_bruskest").returncode == 0
    assert run("./getcert.out wamara stirrer_hewer's").returncode == 0
    
    
