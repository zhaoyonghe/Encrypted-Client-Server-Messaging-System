#!/bin/bash
echo start
CO='\033[1;33m'
NC='\033[0m'
function new_step {
    echo 
    echo -e "${CO}======================================================================${NC}"
    echo -e "${CO}$1${NC}"
    echo -e "${CO}======================================================================${NC}"
}

WORK_DIR=container
ROOT_CA_DIR=${WORK_DIR}/root_ca
INTERMEDIATE_CA_DIR=${WORK_DIR}/intermediate_ca
readonly WORK_DIR
readonly ROOT_CA_DIR
readonly INTERMEDIATE_CA_DIR

# renew the working space
rm -rf ${WORK_DIR}

###################################################################################
# create the root ca
mkdir -p ${ROOT_CA_DIR}
cp root_ca.cnf ${ROOT_CA_DIR}/root_ca.cnf
mkdir ${ROOT_CA_DIR}/private ${ROOT_CA_DIR}/certs ${ROOT_CA_DIR}/newcerts
chmod 700 ${ROOT_CA_DIR}/private

# index.txt and serial: 
# a flat file database to keep track of signed certificates.
touch ${ROOT_CA_DIR}/index.txt
echo 1000 > ${ROOT_CA_DIR}/serial
# TODO: what is this?
touch ${ROOT_CA_DIR}/index.txt.attr

new_step "Generate key pair for the root ca"
openssl genrsa -out ${ROOT_CA_DIR}/private/root_ca.key.pem
chmod 400 ${ROOT_CA_DIR}/private/root_ca.key.pem
new_step "Generate a self-signed root ca certificate"
openssl req -config ${ROOT_CA_DIR}/root_ca.cnf \
    -key ${ROOT_CA_DIR}/private/root_ca.key.pem \
    -new -x509 -days 7300 -sha256 -extensions v3_ca \
    -out ${ROOT_CA_DIR}/certs/root_ca.cert.pem
chmod 444 ${ROOT_CA_DIR}/certs/root_ca.cert.pem

new_step "Check the self-signed certificate"
openssl x509 -noout -text -in ${ROOT_CA_DIR}/certs/root_ca.cert.pem

###################################################################################
# create the immediate ca
mkdir -p ${INTERMEDIATE_CA_DIR}
cp intermediate_ca.cnf ${INTERMEDIATE_CA_DIR}/intermediate_ca.cnf
mkdir ${INTERMEDIATE_CA_DIR}/private ${INTERMEDIATE_CA_DIR}/csr \
    ${INTERMEDIATE_CA_DIR}/certs ${INTERMEDIATE_CA_DIR}/newcerts
chmod 700 ${INTERMEDIATE_CA_DIR}/private

# index.txt and serial: 
# a flat file database to keep track of signed certificates.
touch ${INTERMEDIATE_CA_DIR}/index.txt
echo 1000 > ${INTERMEDIATE_CA_DIR}/serial
# TODO: is that useful?
echo 1000 > ${INTERMEDIATE_CA_DIR}/crlnumber
# TODO: what is this?
touch ${INTERMEDIATE_CA_DIR}/index.txt.attr

new_step "Generate key pair for the intermediate ca"
# TODO: maybe need a input password file?
openssl genrsa -out ${INTERMEDIATE_CA_DIR}/private/intermediate_ca.key.pem
chmod 400 ${INTERMEDIATE_CA_DIR}/private/intermediate_ca.key.pem
new_step "Generate an intermediate ca CSR"
openssl req -config ${INTERMEDIATE_CA_DIR}/intermediate_ca.cnf \
    -new -sha256 \
    -key ${INTERMEDIATE_CA_DIR}/private/intermediate_ca.key.pem \
    -out ${INTERMEDIATE_CA_DIR}/csr/intermediate_ca.csr.pem
new_step "The root ca gives the intermediate ca a signed certificate based on its CSR"
openssl ca -config ${ROOT_CA_DIR}/root_ca.cnf -extensions v3_intermediate_ca \
    -days 3650 -notext -md sha256 \
    -in ${INTERMEDIATE_CA_DIR}/csr/intermediate_ca.csr.pem \
    -out ${INTERMEDIATE_CA_DIR}/certs/intermediate_ca.cert.pem
chmod 444 ${INTERMEDIATE_CA_DIR}/certs/intermediate_ca.cert.pem

cat ${INTERMEDIATE_CA_DIR}/index.txt
new_step "Verify the intermediate certificate"
openssl x509 -noout -text -in ${INTERMEDIATE_CA_DIR}/certs/intermediate_ca.cert.pem
openssl verify -CAfile ${ROOT_CA_DIR}/certs/root_ca.cert.pem \
    ${INTERMEDIATE_CA_DIR}/certs/intermediate_ca.cert.pem

cat ${INTERMEDIATE_CA_DIR}/certs/intermediate_ca.cert.pem \
    ${ROOT_CA_DIR}/certs/root_ca.cert.pem > ${INTERMEDIATE_CA_DIR}/certs/ca-chain.cert.pem
chmod 444 ${INTERMEDIATE_CA_DIR}/certs/ca-chain.cert.pem

###################################################################################
# server certificate
cp msg_server.cnf ${INTERMEDIATE_CA_DIR}/msg_server.cnf
new_step "Generate key pair for the server"
openssl genrsa -out ${INTERMEDIATE_CA_DIR}/private/msg_server.key.pem 2048
chmod 400 ${INTERMEDIATE_CA_DIR}/private/msg_server.key.pem
new_step "Generate a server CSR"
openssl req -config ${INTERMEDIATE_CA_DIR}/msg_server.cnf \
    -new -sha256 \
    -key ${INTERMEDIATE_CA_DIR}/private/msg_server.key.pem \
    -out ${INTERMEDIATE_CA_DIR}/csr/msg_server.csr.pem

new_step "temp: Check the server CSR"
openssl req -text -noout -in ${INTERMEDIATE_CA_DIR}/csr/msg_server.csr.pem

new_step "The intermediate ca gives the server a signed certificate based on its CSR"
openssl ca -config ${INTERMEDIATE_CA_DIR}/intermediate_ca.cnf -extensions server_cert \
    -days 375 -notext -md sha256 \
    -in ${INTERMEDIATE_CA_DIR}/csr/msg_server.csr.pem \
    -out ${INTERMEDIATE_CA_DIR}/certs/msg_server.cert.pem
chmod 444 ${INTERMEDIATE_CA_DIR}/certs/msg_server.cert.pem

new_step "Verify the server certificate"
openssl x509 -noout -text -in ${INTERMEDIATE_CA_DIR}/certs/msg_server.cert.pem
openssl verify -CAfile ${INTERMEDIATE_CA_DIR}/certs/ca-chain.cert.pem \
    ${INTERMEDIATE_CA_DIR}/certs/msg_server.cert.pem

###################################################################################
# client certificate
cp client.cnf ${INTERMEDIATE_CA_DIR}/client.cnf
new_step "Generate key pair for the client"
openssl genrsa -out ${INTERMEDIATE_CA_DIR}/private/client.key.pem 2048
chmod 400 ${INTERMEDIATE_CA_DIR}/private/client.key.pem
new_step "Generate a client CSR"
openssl req -config ${INTERMEDIATE_CA_DIR}/client.cnf \
    -new -sha256 \
    -key ${INTERMEDIATE_CA_DIR}/private/client.key.pem \
    -out ${INTERMEDIATE_CA_DIR}/csr/client.csr.pem
new_step "The intermediate ca gives the client a signed certificate based on its CSR"
openssl ca -config ${INTERMEDIATE_CA_DIR}/intermediate_ca.cnf -extensions usr_cert \
    -days 375 -notext -md sha256 \
    -in ${INTERMEDIATE_CA_DIR}/csr/client.csr.pem \
    -out ${INTERMEDIATE_CA_DIR}/certs/client.cert.pem
chmod 444 ${INTERMEDIATE_CA_DIR}/certs/client.cert.pem

new_step "Verify the client certificate"
openssl x509 -noout -text -in ${INTERMEDIATE_CA_DIR}/certs/client.cert.pem
openssl verify -CAfile ${INTERMEDIATE_CA_DIR}/certs/ca-chain.cert.pem \
    ${INTERMEDIATE_CA_DIR}/certs/client.cert.pem


###################################################################################
# a certificate suitable for others to use when encrypting files to you
cp encryptor.cnf ${INTERMEDIATE_CA_DIR}/encryptor.cnf
new_step "Generate an encryptor certificate"
openssl genrsa -out ${INTERMEDIATE_CA_DIR}/private/encryptor.key.pem 2048
chmod 400 ${INTERMEDIATE_CA_DIR}/private/encryptor.key.pem
new_step "Generate a encryptor CSR"
openssl req -config ${INTERMEDIATE_CA_DIR}/encryptor.cnf \
    -new -sha256 \
    -key ${INTERMEDIATE_CA_DIR}/private/encryptor.key.pem \
    -out ${INTERMEDIATE_CA_DIR}/csr/encryptor.csr.pem
new_step "The intermediate ca gives the encryptor a signed certificate based on its CSR"
openssl ca -config ${INTERMEDIATE_CA_DIR}/intermediate_ca.cnf -extensions encryptor_cert \
    -days 375 -notext -md sha256 \
    -in ${INTERMEDIATE_CA_DIR}/csr/encryptor.csr.pem \
    -out ${INTERMEDIATE_CA_DIR}/certs/encryptor.cert.pem
chmod 444 ${INTERMEDIATE_CA_DIR}/certs/encryptor.cert.pem

new_step "Verify the encryptor certificate"
openssl x509 -noout -text -in ${INTERMEDIATE_CA_DIR}/certs/encryptor.cert.pem
openssl verify -CAfile ${INTERMEDIATE_CA_DIR}/certs/ca-chain.cert.pem \
    ${INTERMEDIATE_CA_DIR}/certs/encryptor.cert.pem

###################################################################################
# a certificate suitable for signing files, including encrypted files
cp signer.cnf ${INTERMEDIATE_CA_DIR}/signer.cnf
new_step "Generate an signer certificate"
openssl genrsa -out ${INTERMEDIATE_CA_DIR}/private/signer.key.pem 2048
chmod 400 ${INTERMEDIATE_CA_DIR}/private/signer.key.pem
new_step "Generate a signer CSR"
openssl req -config ${INTERMEDIATE_CA_DIR}/signer.cnf \
    -new -sha256 \
    -key ${INTERMEDIATE_CA_DIR}/private/signer.key.pem \
    -out ${INTERMEDIATE_CA_DIR}/csr/signer.csr.pem
new_step "The intermediate ca gives the signer a signed certificate based on its CSR"
openssl ca -config ${INTERMEDIATE_CA_DIR}/intermediate_ca.cnf -extensions signer_cert \
    -days 375 -notext -md sha256 \
    -in ${INTERMEDIATE_CA_DIR}/csr/signer.csr.pem \
    -out ${INTERMEDIATE_CA_DIR}/certs/signer.cert.pem
chmod 444 ${INTERMEDIATE_CA_DIR}/certs/signer.cert.pem

new_step "Verify the signer certificate"
openssl x509 -noout -text -in ${INTERMEDIATE_CA_DIR}/certs/signer.cert.pem
openssl verify -CAfile ${INTERMEDIATE_CA_DIR}/certs/ca-chain.cert.pem \
    ${INTERMEDIATE_CA_DIR}/certs/signer.cert.pem