#include <unistd.h>
#include <fstream>
#include <iostream>
#include <sstream>

#include "client.hpp"
#include "openssl-sign-by-ca-master/openssl1.1/main.c"

// Generate and save key and csr. Return csr for get_cert usage
std::string generate_key_and_csr(const std::string& username)
{
    // Generate key and csr
    X509_REQ *req = NULL;
    EVP_PKEY *key = NULL;
    generate_key_csr(&key, &req);

    // Convert key and csr to pem
    uint8_t *key_bytes = NULL;
    uint8_t *csr_bytes = NULL;
    size_t key_size = 0;
    size_t csr_size = 0;
    key_to_pem(key, &key_bytes, &key_size);
    csr_to_pem(req, &csr_bytes, &csr_size);

    // Save key to local location and return csr
    std::ofstream key_pem_file("./" + username + "_private_key.pem");
    key_pem_file << key_bytes;
    key_pem_file.close();

    std::ostringstream csr_pem_stream;
    csr_pem_stream << csr_bytes;
    std::string csr_pem_string = csr_pem_stream.str();

    // Free stuff
    EVP_PKEY_free(key);
    X509_REQ_free(req);
    free(key_bytes);
    free(csr_bytes);

    return csr_pem_string;
}

int main(int argc, char *argv[])
{
    Info info;
    info.action = getcert;

    if (argc <= 1)
    {
        fprintf(stderr, "Please enter enough parameters!\n");
        exit(1);
    }

    if (argc > 3)
    {
        fprintf(stderr, "Too many parameters!");
        exit(1);
    }

    // argc is 2 or 3
    info.username = std::string(argv[1]);
    info.password = (argc == 2) ? std::string(getpass("Input a password:")) : std::string(argv[2]);

    info.csr = generate_key_and_csr(info.username);
    info.print_info();

    std::string code, body;
    client_send(info, code, body);

    // If get 200 OK, save received certificate
    if (code == "200")
    {
        std::ofstream certificate_pem_file("./" + info.username + "_certificate.pem");
        certificate_pem_file << body;
        certificate_pem_file.close();
    }

    return 0;
}