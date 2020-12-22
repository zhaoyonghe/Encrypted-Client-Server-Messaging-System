#include <unistd.h>
#include <fstream>
#include <iostream>
#include <sstream>

#include "client.hpp"
#include "openssl-sign-by-ca-master/openssl1.1/main.cpp"

int main(int argc, char* argv[]) {
    Info info;
    info.action = changepw;
    std::string private_key_path = "";

    if (argc <= 1 or argc > 4) {
        // argc must be 1 to 3
        fprintf(stderr, "Usage: changepw <username> <password>? <new_password>?\n");
        exit(1);
    }

    // argc is 2, 3 or 4
    info.username = std::string(argv[1]);
    info.password = (argc == 2) ? std::string(getpass("Input a password:")) : std::string(argv[2]);
    info.new_password = (argc == 3) ? std::string(getpass("Input a new password:")) : std::string(argv[3]);

    std::string key, csr;
    generate_key_and_csr(info.username, key, csr);
    info.csr = csr;
    // info.print_info();

    std::string code, body;
    client_send(info, code, body, private_key_path);

    // If get 200 OK, save key and received certificate
    if (code == "200") {
        std::ofstream key_pem_file("./" + info.username + "_private_key.pem");
        key_pem_file << key;
        key_pem_file.close();

        std::ofstream certificate_pem_file("./" + info.username + "_certificate.pem");
        certificate_pem_file << body;
        certificate_pem_file.close();

        fprintf(stdout, "Password is changed!\nGot a new certificate:\n\n%s\n", body.c_str());
    } else {
        fprintf(stderr, "Error from server: %s.\n", body.c_str());
        exit(1);
    }

    return 0;
}