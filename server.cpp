#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <sstream>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/stat.h>

#include "info.hpp"
#include "my.hpp"

bool verify_password(std::string username, std::string password) {
    std::string hased_pw_path = "hashed_pw/" + username;
    struct stat buffer;

    if (stat(hased_pw_path.c_str(), &buffer) != 0) {
        // This user does not exist.
        return false;
    }

    if (buffer.st_size != 106) {
        // This file might be tampered.
        return false;
    }

    std::ifstream t(hased_pw_path);
    std::stringstream stream;
    stream << t.rdbuf();

    return strcmp(stream.str().c_str(), crypt(password.c_str(), stream.str().c_str())) == 0;
}

int main() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ssl_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
    auto ssl_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
    SSL_CTX_set_min_proto_version(ssl_ctx.get(), TLS1_2_VERSION);
#endif

    if (!SSL_CTX_use_certificate_file(ssl_ctx.get(), "certs/msg_server.cert.pem", SSL_FILETYPE_PEM)) {
        my::print_errors_and_exit("Error loading server certificate");
    }
    if (!SSL_CTX_use_PrivateKey_file(ssl_ctx.get(), "private/msg_server.key.pem", SSL_FILETYPE_PEM)) {
        my::print_errors_and_exit("Error loading server private key");
    }
    if (!SSL_CTX_load_verify_locations(ssl_ctx.get(), "certs/ca-chain.cert.pem", nullptr)) {
        my::print_errors_and_exit("Error setting up trust store");
    }

    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept("4399"));
    if (BIO_do_accept(accept_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_accept (binding to port 4399)");
    }

    static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
        close(fd);
    };
    signal(SIGINT, [](int) { shutdown_the_socket(); });

    printf("Server running\n");

    std::string header_get = "GET /";
    std::string header_post = "POST /";
    while (auto conn_bio = my::accept_new_tcp_connection(accept_bio.get())) {
        conn_bio = std::move(conn_bio) | my::UniquePtr<BIO>(BIO_new_ssl(ssl_ctx.get(), 0));
        try {
            std::string request = my::receive_http_message(conn_bio.get());
            printf("Got request:\n");
            printf("%s\n", request.c_str());

            // Parse request here
            std::string action;
            std::size_t get_index = request.find(header_get);
            if (get_index != std::string::npos) {
                action = request[get_index + header_get.length()];
            } else {
                std::size_t post_index = request.find(header_post);
                if (post_index != std::string::npos) {
                    action = request[post_index + header_post.length()];
                } else {
                    my::send_http_response(conn_bio.get(), "no valid action type found\n");
                    continue;
                }
            }

            // Display action type
            int action_num = std::stoi(action, nullptr, 10);
            std::string action_string;
            switch (action_num) {
            case getcert:
                action_string = "getcert";
                std::cout << verify_password("addleness", "Cardin_pwns") << std::endl;
                std::cout << verify_password("addleness ", "Cardin_pwns") << std::endl;
                std::cout << verify_password("addleness", "Cardn_pwns") << std::endl;
                std::cout << verify_password("overrich", "Cardin_pwns") << std::endl;
                break;
            case changepw:
                action_string = "changepw";
                break;
            case sendmsg:
                action_string = "sendmsg";
                break;
            case recvmsg:
                action_string = "recvmsg";
                break;
            default:
                action_string = "none";
            }

            printf("Got action: %s\n", action_string.c_str());

            my::send_http_response(conn_bio.get(), "okay cool\n");
        } catch (const std::exception& ex) {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
    }
    printf("\nClean exit!\n");
}