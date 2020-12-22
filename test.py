#!/usr/bin/python3

import subprocess
import string
import random

def step(description):
    print()
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

def forever():
    while True:
        for cmd in ["./getcert.out addleness Cardin_pwns", "./getcert.out overrich Freemasonry_bruskest", "./getcert.out wamara stirrer_hewer's"]:
            res = run(cmd)
            assert res.returncode == 0
            assert res.stdout.startswith("Got a certificate:\n\n-----BEGIN CERTIFICATE-----")
            assert res.stdout.strip().endswith("-----END CERTIFICATE-----")
            assert res.stderr == "" 

def functional_testing():
    step("Users cannot login with incorrect password.")
    for cmd in ["./getcert.out addleness hjglgy", "./getcert.out overrich 234523b4kb234t", "./getcert.out wamara c,,,,,cc"]:
        res = run(cmd)
        assert res.returncode == 1
        assert res.stdout == ""
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
        assert res.stdout == ""
        assert res.stderr.startswith("Error from server:")

    step("Users cannot login with certificate signed by untrusted ca chain.")
    res = run("./sendmsg.out ./malicious_cert/container/intermediate_ca/certs/malicious_client_certificate.pem ./malicious_cert/container/intermediate_ca/private/malicious_client_private_key.pem ./play.cpp overrich")
    res = run("./recvmsg.out ./malicious_cert/container/intermediate_ca/certs/malicious_client_certificate.pem ./malicious_cert/container/intermediate_ca/private/malicious_client_private_key.pem")

    step("Users can send messages with certificate to other users with certificate.")
    names = ["addleness", "overrich", "wamara"]
    s = len(names)
    for i in range(s):
        cmd = "./sendmsg.out ./%s_certificate.pem ./%s_private_key.pem ./play.cpp %s" % (names[i], names[i], names[(i+1)%s])
        res = run(cmd)
        assert res.returncode == 0
        assert res.stdout == "Message has been sent to %s successfully.\n" % names[(i+1)%s]
        assert res.stderr == ""

    step("Users cannot send messages with incorrect key pair.")
    names = ["addleness", "overrich", "wamara"]
    s = len(names)
    for i in range(s):
        cmd = "./sendmsg.out ./%s_certificate.pem ./%s_private_key.pem ./play.cpp %s" % (names[i], names[(i+1)%s], names[(i+2)%s])
        res = run(cmd)
        assert res.returncode == 1
        assert res.stdout == ""
        assert res.stderr.startswith("Error loading client private key")

    step("Users cannot send messages to users without certificate.")
    for name in ["addleness", "overrich", "wamara"]:
        cmd = "./sendmsg.out ./%s_certificate.pem ./%s_private_key.pem ./play.cpp analects" % (name, name)
        res = run(cmd)
        assert res.returncode == 0
        assert res.stdout == ""
        assert res.stderr == "Message cannot be sent to analects: try to load an nonexistent certificate (no such user or this user does not have a certificate).\n"

    step("Users cannot send messages to an nonexistent user.")
    for name in ["addleness", "overrich", "wamara"]:
        cmd = "./sendmsg.out ./%s_certificate.pem ./%s_private_key.pem ./play.cpp a" % (name, name)
        res = run(cmd)
        assert res.returncode == 0
        assert res.stdout == ""
        assert res.stderr == "Message cannot be sent to a: try to load an nonexistent certificate (no such user or this user does not have a certificate).\n"

    step("Users cannot changepw with messages in mailbox.")
    for name in ["addleness", "overrich", "wamara"]:
        cmd = "./changepw.out %s %s xx" % (name, name[0]*3)
        res = run(cmd)
        assert res.returncode == 1
        assert res.stdout == ""
        assert res.stderr == "Error from server: there are still unread message(s) in the user's mailbox.\n"
    
    content = open('play.cpp', 'r').read()
    m = content + "\n\n========================================================================\n" \
    + "Verified the identity of the sender and decrypted the message successfully, see above.\n"
    # print(m)
    step("Users can receive the message.")
    for name in ["addleness", "overrich", "wamara"]:
        cmd = "./recvmsg.out ./%s_certificate.pem ./%s_private_key.pem" % (name, name)
        res = run(cmd)
        assert res.returncode == 0
        assert res.stdout == m
        assert res.stderr == ""

    step("Users cannot receive the message when its mailbox is empty.")
    for name in ["addleness", "overrich", "wamara"]:
        cmd = "./recvmsg.out ./%s_certificate.pem ./%s_private_key.pem" % (name, name)
        res = run(cmd)
        assert res.returncode == 1
        assert res.stdout == ""
        assert res.stderr == "Error from server: no unread message.\n"

    step("Sender identity check will fail after the sender changed its certificate.")
    run("./sendmsg.out ./addleness_certificate.pem ./addleness_private_key.pem ./play.cpp overrich")
    run("./getcert.out addleness aaa")
    res = run("./recvmsg.out ./overrich_certificate.pem ./overrich_private_key.pem")
    assert res.returncode == 1
    assert res.stdout == ""
    assert res.stderr.startswith("Fail to verify the identity of the sender!\n")

def fuzz_testing():
    step("Fuzz testing.")
    for _ in range(10):
        res = run(get_random_cmd(["./getcert.out"]))
        assert res.returncode == 1
        assert res.stderr.startswith("Error from server:") or res.stderr.startswith("Usage")
    for _ in range(10):
        res = run(get_random_cmd(["./getcert.out", "addleness"], 1, 1))
        assert res.returncode == 1
        assert res.stderr.startswith("Error from server:")
    for _ in range(10):
        res = run(get_random_cmd(["./changepw.out"], 3, 7))
        assert res.returncode == 1
        assert res.stderr.startswith("Error from server:") or res.stderr.startswith("Usage")
    for _ in range(10):
        res = run(get_random_cmd(["./changepw.out", "addleness"], 2, 2))
        assert res.returncode == 1
        assert res.stderr.startswith("Error from server:")
    for _ in range(10):
        res = run(get_random_cmd(["./sendmsg.out"], 0, 5))
        assert res.returncode == 1
        assert res.stderr.startswith("Error loading client certificate") or res.stderr.startswith("Usage")
    for _ in range(10):
        res = run(get_random_cmd(["./recvmsg.out"], 0, 3))
        assert res.returncode == 1
        assert res.stderr.startswith("Error loading client certificate") or res.stderr.startswith("Usage")

if __name__ == "__main__":
    functional_testing()
    fuzz_testing()