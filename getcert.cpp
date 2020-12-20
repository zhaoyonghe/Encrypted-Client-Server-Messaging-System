#include <unistd.h>
#include <fstream>
#include <iostream>
#include <sstream>

#include "client.hpp"
#include "openssl-sign-by-ca-master/openssl1.1/main.c"

int main(int argc, char* argv[])
{
    Info info;
    info.action = getcert;
    std::string private_key_path = "";

    if (argc <= 1 or argc > 3) {
        // argc must be 1 or 2
        fprintf(stderr, "Usage: getcert <username> <password>?");
        exit(1);
    }

    // argc is 2 or 3
    info.username = std::string(argv[1]);
    info.password = (argc == 2) ? std::string(getpass("Input a password:")) : std::string(argv[2]);

    std::string key, csr;
    generate_key_and_csr(key, csr);
    info.csr = csr;
    info.print_info();

    std::string code, body;
    client_send(info, code, body, private_key_path);

    // If get 200 OK, save key and received certificate
    if (code == "200")
    {
        std::ofstream key_pem_file("./" + info.username + "_private_key.pem");
        key_pem_file << key;
        key_pem_file.close();

        std::ofstream certificate_pem_file("./" + info.username + "_certificate.pem");
        certificate_pem_file << body;
        certificate_pem_file.close();
    }

    return 0;
}