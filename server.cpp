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
#include <ctype.h>
#include <exception>      
#include <streambuf>


#include "info.hpp"
#include "my.hpp"
#include "openssl-sign-by-ca-master/openssl1.1/main.c"

Action char_to_action(char c) {
    if (!isdigit(c)) {
        return unsupport;
    }
    return ((c - '0') >= unsupport) ? unsupport : (Action)(c - '0');
}

Action get_action_from_request(std::string& request, int index) {
    if (index >= request.length()) {
        return unsupport;
    }
    return char_to_action(request[index]);
}

Action get_action_from_request(std::string& request) {
    std::string header_get = "GET /";
    std::string header_post = "POST /";

    std::size_t get_index = request.find(header_get);
    if (get_index != std::string::npos) {
        return get_action_from_request(request, get_index + header_get.length());
    }

    std::size_t post_index = request.find(header_post);
    if (post_index != std::string::npos) {
        return get_action_from_request(request, post_index + header_post.length());
    }

    return unsupport;
}

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

// Simply sign a new certificate for client and send it to client
// Returns http code
// TODO: How to specify configuration?
std::string handle_getcert(std::string& response, std::string& ca_cert_path, std::string& ca_key_path, std::string& csr_string, std::string username) {
    // Load CA key and cert.
    EVP_PKEY* ca_key = NULL;
    X509* ca_crt = NULL;
    if (!load_ca(ca_key_path.c_str(), &ca_key, ca_cert_path.c_str(), &ca_crt)) {
        std::string err_msg = "Failed to load CA certificate and/or key!\n";
        std::cout << err_msg;
        response = err_msg;
        return "400";
    }

    // Load certificate signing request
    X509_REQ* csr = NULL;
    auto csr_bio = my::UniquePtr<BIO>(BIO_new_mem_buf(csr_string.c_str(), csr_string.length()));
    csr = PEM_read_bio_X509_REQ(csr_bio.get(), NULL, NULL, NULL);

    // Generate keypair and then print it byte-by-byte for demo purposes.
    EVP_PKEY* key = NULL;
    X509* crt = NULL;
    int ret = generate_signed_key_pair(csr, ca_key, ca_crt, &key, &crt);
    if (!ret) {
        std::string err_msg = "Failed to generate key pair!\n";
        std::cout << err_msg;
        response = err_msg;
        return "406";
    }

    // Convert key and certificate to PEM format.
    // uint8_t *key_bytes = NULL;
    // size_t key_size = 0;
    // key_to_pem(key, &key_bytes, &key_size);
    // print_bytes(key_bytes, key_size);

    uint8_t* crt_bytes = NULL;
    size_t crt_size = 0;
    crt_to_pem(crt, &crt_bytes, &crt_size);
    print_bytes(crt_bytes, crt_size);

    // Save signed certificate
    std::ofstream certificate_pem_file("./certs/users/" + username + "_certificate.pem");
    certificate_pem_file << crt_bytes;
    certificate_pem_file.close();

    std::ostringstream certificate_pem_stream;
    certificate_pem_stream << crt_bytes;
    std::string certificate_pem_string = certificate_pem_stream.str();

    // Free stuff.
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(key);
    X509_free(ca_crt);
    X509_free(crt);
    X509_REQ_free(csr);
    //free(key_bytes);
    free(crt_bytes);

    response = certificate_pem_string;
    return "200";
}

std::string handle_sendmsg() {
    return "200";
}

int main() {
    std::string ca_cert_path = "./certs/intermediate_ca.cert.pem";
    std::string ca_key_path = "./private/intermediate_ca.key.pem";

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

    while (true) {
        //BIO_reset(accept_bio.get());
        auto conn_bio = my::accept_new_tcp_connection(accept_bio.get());
        auto ssl_bio = std::move(conn_bio) | my::UniquePtr<BIO>(BIO_new_ssl(ssl_ctx.get(), 0));
        try {
            std::string request = my::receive_http_message(ssl_bio.get());
            printf("Got request:\n");
            printf("%s\n", request.c_str());

            // Parse request here
            Action action = get_action_from_request(request);
            std::string action_string;
            std::string response = "okay cool\n";
            std::string http_code = "200";

            if (action == getcert) {
                action_string = "getcert";
                Info info;
                char* end_of_headers = strstr(&request[0], "\r\n\r\n");
                std::string body = std::string(end_of_headers + 4, &request[request.size()]);
                printf("%s\n", body.c_str());
                printf("%d--\n", info.from_string(body));
                info.print_info();

                if (verify_password(info.username, info.password)) {
                    http_code = handle_getcert(response, ca_cert_path, ca_key_path, info.csr, info.username);
                } else {
                    http_code = "401";
                    response = "username password mismatch\n";
                }
            } else if (action == changepw) {
                action_string = "changepw";
            } else if (action == sendmsg) {
                action_string = "sendmsg";
            } else if (action == recvmsg) {
                action_string = "recvmsg";
            } else {
                action_string = "none";
            }

            printf("Got action: %s\n", action_string.c_str());
            my::send_http_response(ssl_bio.get(), http_code, response);
        } catch (const std::exception& ex) {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
    }
    printf("\nClean exit!\n");
}