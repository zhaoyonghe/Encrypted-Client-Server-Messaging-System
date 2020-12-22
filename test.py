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
    print(a)
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

def fuzzy_testing():
    for _ in range(10):
        res = run(get_random_cmd(["./getcert.out"]))
        assert res.returncode == 1
        assert res.stderr.startswith("Error from server:")
    for _ in range(10):
        res = run("./getcert.out addleness " + get_radom_string())
        assert res.returncode == 1
        assert res.stderr.startswith("Error from server:")

def forever():
    while True:
        for cmd in ["./getcert.out addleness Cardin_pwns", "./getcert.out overrich Freemasonry_bruskest", "./getcert.out wamara stirrer_hewer's"]:
            res = run(cmd)
            assert res.returncode == 0
            assert res.stdout.startswith("Got a certificate:\n\n-----BEGIN CERTIFICATE-----")
            assert res.stdout.strip().endswith("-----END CERTIFICATE-----")
            assert res.stderr == "" 

if __name__ == "__main__":
    step("Users cannot login with incorrect password.")
    for cmd in ["./getcert.out addleness hjglgy", "./getcert.out overrich 234523b4kb234t", "./getcert.out wamara c,,,,,cc"]:
        res = run(cmd)
        assert res.returncode == 1
        assert res.stderr.startswith("Error from server:")
    
    step("Users can getcert with correct username/password pair.")
    for cmd in ["./getcert.out addleness Cardin_pwns", "./getcert.out overrich Freemasonry_bruskest", "./getcert.out wamara stirrer_hewer's"]:
        res = run(cmd)
        assert res.returncode == 0
        assert res.stdout.startswith("Got a certificate:\n\n-----BEGIN CERTIFICATE-----")
        assert res.stdout.strip().endswith("-----END CERTIFICATE-----")
        assert res.stderr == ""
    
    step("Users can changepw with correct username/passsword pair.")
    for cmd in ["./changepw.out addleness Cardin_pwns aaa", "./changepw.out overrich Freemasonry_bruskest ooo", "./changepw.out wamara stirrer_hewer's www"]:
        res = run(cmd)
        assert res.returncode == 0
        assert res.stdout.startswith("Password is changed!\nGot a new certificate:\n\n-----BEGIN CERTIFICATE-----")
        assert res.stdout.strip().endswith("-----END CERTIFICATE-----")
        assert res.stderr == ""

    step("Users can login with new password.")
    for cmd in ["./getcert.out addleness aaa", "./getcert.out overrich ooo", "./getcert.out wamara www"]:
        res = run(cmd)
        assert res.returncode == 0
        assert res.stdout.startswith("Got a certificate:\n\n-----BEGIN CERTIFICATE-----")
        assert res.stdout.strip().endswith("-----END CERTIFICATE-----")
        assert res.stderr == ""

    step("Users cannot login with previous password.")
    for cmd in ["./getcert.out addleness Cardin_pwns", "./getcert.out overrich Freemasonry_bruskest", "./getcert.out wamara stirrer_hewer's"]:
        res = run(cmd)
        assert res.returncode == 1
        assert res.stderr.startswith("Error from server:")

    # step("Users can send messages with certificate to other users with certificate.")
    # assert run("./sendmsg.out ./addleness_certificate.pem ./addleness_private_key.pem ./play.cpp overrich").returncode == 0
    # assert run("./sendmsg.out ./overrich_certificate.pem ./overrich_private_key.pem ./play.cpp wamara").returncode == 0
    # assert run("./sendmsg.out ./wamara_certificate.pem ./wamara_private_key.pem ./play.cpp addleness").returncode == 0

    # step("Users cannot send messages with incorrect key pair.")
    # assert run("./sendmsg.out ./addleness_certificate.pem ./wamara_private_key.pem ./play.cpp overrich").returncode == 1
    # assert run("./sendmsg.out ./overrich_certificate.pem ./addleness_private_key.pem ./play.cpp wamara").returncode == 1
    # assert run("./sendmsg.out ./wamara_certificate.pem ./overrich_private_key.pem ./play.cpp addleness").returncode == 1

    # step("Users cannot send messages to users without certificate.")
    # assert run("./sendmsg.out ./addleness_certificate.pem ./addleness_private_key.pem ./play.cpp analects").returncode == 1
    # assert run("./sendmsg.out ./overrich_certificate.pem ./overrich_private_key.pem ./play.cpp analects").returncode == 1
    # assert run("./sendmsg.out ./wamara_certificate.pem ./wamara_private_key.pem ./play.cpp analects").returncode == 1

    # step("Users cannot send messages to nonexistent users.")
    # assert run("./sendmsg.out ./addleness_certificate.pem ./addleness_private_key.pem ./play.cpp a").returncode == 1
    # assert run("./sendmsg.out ./overrich_certificate.pem ./overrich_private_key.pem ./play.cpp a").returncode == 1
    # assert run("./sendmsg.out ./wamara_certificate.pem ./wamara_private_key.pem ./play.cpp a").returncode == 1

    # step("Users cannot changepw with messages in mailbox.")
    # assert run("./changepw.out addleness aaa bbb").returncode == 1
    # assert run("./changepw.out overrich ooo ccc").returncode == 1
    # assert run("./changepw.out wamara www ddd").returncode == 1