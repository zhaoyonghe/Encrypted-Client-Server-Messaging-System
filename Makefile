SERVER_SANDBOX = msg_server_sandbox
SERVER_SANDBOX_CERTS = $(SERVER_SANDBOX)/certs
SERVER_SANDBOX_PRIVATE = $(SERVER_SANDBOX)/private
SERVER_SANDBOX_HASHED_PW = $(SERVER_SANDBOX)/hashed_pw
SERVER_SANDBOX_USERS = $(SERVER_SANDBOX)/users

default:
	g++ -o client.out client.cpp -lssl -lcrypto
	g++ -o server.out server.cpp -lssl -lcrypto

install: server getcert changepw sendmsg recvmsg
	echo "not implemented"

server:
	rm -rf $(SERVER_SANDBOX)
	mkdir -p $(SERVER_SANDBOX)
	mkdir -p $(SERVER_SANDBOX_CERTS)
	mkdir -p $(SERVER_SANDBOX_CERTS)/users
	mkdir -p $(SERVER_SANDBOX_PRIVATE)
	mkdir -p $(SERVER_SANDBOX_HASHED_PW)
	mkdir -p $(SERVER_SANDBOX_USERS)
	g++ -o server.out server.cpp my.cpp -lssl -lcrypto -lcrypt
	cp server.out $(SERVER_SANDBOX)
	cp certs/container/intermediate_ca/certs/msg_server.cert.pem $(SERVER_SANDBOX_CERTS)/msg_server.cert.pem
	cp certs/container/intermediate_ca/certs/ca-chain.cert.pem $(SERVER_SANDBOX_CERTS)/ca-chain.cert.pem
	cp certs/container/intermediate_ca/private/msg_server.key.pem $(SERVER_SANDBOX_PRIVATE)/msg_server.key.pem
	cp certs/container/intermediate_ca/certs/intermediate_ca.cert.pem $(SERVER_SANDBOX_CERTS)/intermediate_ca.cert.pem
	cp certs/container/intermediate_ca/private/intermediate_ca.key.pem $(SERVER_SANDBOX_PRIVATE)/intermediate_ca.key.pem
	cp users/hashed_pw/* $(SERVER_SANDBOX_HASHED_PW)
	cp -r users/users/* $(SERVER_SANDBOX_USERS)

four: getcert changepw sendmsg recvmsg

getcert:
	g++ -o getcert.out getcert.cpp client.cpp my.cpp -lssl -lcrypto

changepw:
	g++ -o changepw.out changepw.cpp client.cpp my.cpp -lssl -lcrypto

sendmsg:
	g++ -o sendmsg.out sendmsg.cpp client.cpp cms.cpp my.cpp -lssl -lcrypto

recvmsg:
	g++ -o recvmsg.out recvmsg.cpp client.cpp cms.cpp my.cpp -lssl -lcrypto

cms:
	g++ -o cms.out cms.cpp -lssl -lcrypto

sandbox_build:
	docker build -t yz3645/sandbox:0.1 .

sandbox_run:
	docker run -p 4399:4399 --rm -ti yz3645/sandbox:0.1

clean:
	rm -rf *.out
	rm -rf $(SERVER_SANDBOX)
	rm -rf *.txt
	rm -rf *.pem