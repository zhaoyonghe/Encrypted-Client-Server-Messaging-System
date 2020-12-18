default:
	g++ -o client.out client.cpp -lssl -lcrypto
	g++ -o server.out server.cpp -lssl -lcrypto

install: getcert changepw sendmsg recvmsg server
	rm -rf msg_server_sandbox
	mkdir msg_server_sandbox
	cp server.out msg_server_sandbox

server:
	echo "Not implemented"

getcert:
	g++ -o getcert.out getcert.cpp -lssl -lcrypto

changepw:
	g++ -o changepw.out changepw.cpp -lssl -lcrypto

sendmsg:
	g++ -o sendmsg.out sendmsg.cpp -lssl -lcrypto

recvmsg:
	g++ -o recvmsg.out recvmsg.cpp -lssl -lcrypto

clean:
	rm -rf *.out