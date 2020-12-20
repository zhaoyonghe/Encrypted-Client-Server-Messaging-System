SERVER_SANDBOX = msg_server_sandbox
SERVER_SANDBOX_CERTS = $(SERVER_SANDBOX)/certs
SERVER_SANDBOX_PRIVATE = $(SERVER_SANDBOX)/private
SERVER_SANDBOX_HASHED_PW = $(SERVER_SANDBOX)/hashed_pw

default:
	g++ -o client.out client.cpp -lssl -lcrypto
	g++ -o server.out server.cpp -lssl -lcrypto

install: server getcert changepw sendmsg recvmsg
	echo "not implemented"

server:
	rm -rf $(SERVER_SANDBOX)
	mkdir -p $(SERVER_SANDBOX)
	mkdir -p $(SERVER_SANDBOX)/certs
	mkdir -p $(SERVER_SANDBOX)/certs/users
	mkdir -p $(SERVER_SANDBOX)/private
	mkdir -p $(SERVER_SANDBOX)/hashed_pw
	g++ -o server.out server.cpp -lssl -lcrypto -lcrypt
	cp server.out $(SERVER_SANDBOX)
	cp certs/container/intermediate_ca/certs/msg_server.cert.pem $(SERVER_SANDBOX_CERTS)/msg_server.cert.pem
	cp certs/container/intermediate_ca/certs/ca-chain.cert.pem $(SERVER_SANDBOX_CERTS)/ca-chain.cert.pem
	cp certs/container/intermediate_ca/private/msg_server.key.pem $(SERVER_SANDBOX_PRIVATE)/msg_server.key.pem
	cp certs/container/intermediate_ca/certs/intermediate_ca.cert.pem $(SERVER_SANDBOX_CERTS)/intermediate_ca.cert.pem
	cp certs/container/intermediate_ca/private/intermediate_ca.key.pem $(SERVER_SANDBOX_PRIVATE)/intermediate_ca.key.pem
	cp hashed_pw/hashed_pw/* $(SERVER_SANDBOX_HASHED_PW)

getcert:
	g++ -o getcert.out getcert.cpp client.cpp -lssl -lcrypto

changepw:
	g++ -o changepw.out changepw.cpp client.cpp -lssl -lcrypto

sendmsg:
	g++ -o sendmsg.out sendmsg.cpp client.cpp -lssl -lcrypto

recvmsg:
	g++ -o recvmsg.out recvmsg.cpp client.cpp -lssl -lcrypto

clean:
	rm -rf *.out
	rm -rf $(SERVER_SANDBOX)