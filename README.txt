COMSW 4181 Security 1 Final Project
Team name: Team ASAP
Team members: Yiyang Zeng (yz3645), Yonghe Zhao (yz3687)

~~~~~~~~How to build and use~~~~~~~~
To run our project correctly, please make sure that the machine has the openssl library and docker installed (with docker daemon launched).

You can simply use “make install” to build everything: the server docker image, four client commands binaries and a fuzz testing binary.
Then use “make sandbox_run” to run the docker image, which will automatically set up the server for handling messages from the client. 
Use the client commands with the following syntax:
./getcert.out <username> <password>?
./changepw.out <username> <password>? <new_password>?
./sendmsg.out <certpath> <privkeypath> <msgpath> <receipient>+
./recvmsg.out <certpath> <privkeypath>
You can also use “python3 test.py” to run our test script, which includes functional testing and fuzz testing.

~~~~~~~~File layout~~~~~~~~
In our project, the root folder contains all the source files. 
./certs contains all the certificates that make the server and client work: the server certificate and certificates of the trusted CA chain.
./malicious_cert contains some bad certificates used for testing: client certificates signed by an untrustworthy CA chain.
./users contains the users list and a script to generate server mailboxes for users. 
./openssl-sign-by-ca-master contains an open-source project we reference. Note that the code in the referenced project is heavily modified to suit our use case. 
./tmp is used to store temporary files that will be created and used during operations. 
Makefile details the commands involved in running the project.

~~~~~~~~Functionality~~~~~~~~
The general functionality of our project is the same as described in the assignment. 
There are a few points to emphasize:
-For unknown users (users not in the given list): They do not have a valid username/password, so they cannot run getcert and changepw successfully (will not pass the username/password verification). They do not have certificate/private key, so they cannot run sendmsg and recvmsg successfully (will not pass the TLS verification).
-For unauthorized users (users in the given list but without valid certificate-key pair): the client and server use certificates to verify each other’s identity when necessary, so it is impossible for attackers to do anything meaningful without compromised valid private keys, certificates and usernames and passwords. We assume attackers won’t get their hands on these with our proper sandboxing. 
-For authorized users (users with valid certificate-key pair) : They cannot disguise themselves as other users, since they do not have the private key of the other users. The usernames are baked into certificates, so the server can check the username on certificates to decide who is talking to the server. 

~~~~~~~~Sandboxing~~~~~~~~
Only the server is sandboxed using Docker, so that the file store on the server side won’t be sabotaged by attackers. Certificates (of CA and server), usernames, hashed passwords, encrypted messages are all stored securely in the sandboxed server. 

~~~~~~~~Testing~~~~~~~~
Our test plan includes two parts: functional testing and fuzz testing. Please check test.py for more details. This test script is highly readable and we highly recommend you to read it to understand our testing logic.

Functional testing is to test if the behavior of the client-server interaction is what we expected by checking the output (return code, stdout, stderr) of different scenarios. In the test.py, we emulate a lot of scenarios, including correct/clean interaction and some simple attacks (like “try to log in with a certificate signed by an untrustworthy CA chain”).

Fuzz testing is to test if the client and server can handle the random/malicious input decently and does not crash. We first test some random input strings into four binaries. Then we test some random request body sending directly to the server (Here, we assume the random request has valid HTTP headers, especially the “Content-length” header and “\r\n\r\n” to split the headers and body. Currently, without the “Content-length” header, our server cannot know when to stop the request receiving and will keep waiting for the incoming request.).

The results show that our client/server can interact with each other correctly under different scenarios and can deal with the random inputs/requests decently (does not crush; does not perform any malicious operation).


~~~~~~~~Reference~~~~~~~~

openssl-sign-by-ca (https://github.com/zozs/openssl-sign-by-ca)
