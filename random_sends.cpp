#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>

#include "my.hpp"
#include "info.hpp"

#include <time.h> 
#include <random> 


int client_send(Info& info, std::string& private_key_path, std::string& bad_string) {
    std::string address = "www.msg_server.com";
    char msg_header[50];
    sprintf(msg_header, "POST /%d HTTP/1.1", info.action);
    std::string host_port = "localhost:4399";


    /* Set up the SSL context */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ssl_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
    auto ssl_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif

    // load self certificate, private key and CA certificate (to verify the identity of the connection peer)
    if (info.action != getcert && info.action != changepw) {
        if (!SSL_CTX_use_certificate_file(ssl_ctx.get(), info.cert_path.c_str(), SSL_FILETYPE_PEM)) {
            my::print_errors_and_exit("Error loading client certificate");
        }
        if (!SSL_CTX_use_PrivateKey_file(ssl_ctx.get(), private_key_path.c_str(), SSL_FILETYPE_PEM)) {
            my::print_errors_and_exit("Error loading client private key");
        }
    }
    if (!SSL_CTX_load_verify_locations(ssl_ctx.get(), "./certs/container/intermediate_ca/certs/ca-chain.cert.pem", nullptr)) {
        my::print_errors_and_exit("Error setting up trust store");
    }

    auto conn_bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:4399"));
    if (conn_bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(conn_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect");
    }

    auto ssl_bio = std::move(conn_bio) | my::UniquePtr<BIO>(BIO_new_ssl(ssl_ctx.get(), 1));
    // Add the destination domain in plaintext as part of the TLS handshake.
    // It goes in a field called “Server Name Indication” (SNI).
    SSL_set_tlsext_host_name(my::get_ssl(ssl_bio.get()), address.c_str());
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set1_host(my::get_ssl(ssl_bio.get()), address.c_str());
#endif

    if (BIO_do_handshake(ssl_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_handshake");
    }
    my::verify_the_certificate(my::get_ssl(ssl_bio.get()), address.c_str());

    if (info.action == getcert || info.action == changepw) {
        my::send_http_post(ssl_bio.get(), msg_header, host_port, bad_string);
    } else if (info.action == sendmsg_get_recipient_cert) {
        my::send_http_post(ssl_bio.get(), msg_header, host_port, bad_string);
    } else if (info.action == sendmsg_send_encrypted_signed_message) {
        my::send_http_post(ssl_bio.get(), msg_header, host_port, bad_string);
    } else if (info.action == recvmsg) {
        my::send_http_post(ssl_bio.get(), msg_header, host_port, bad_string);
    } else {
        return 1;
    }

    std::string response = my::receive_http_message(ssl_bio.get());
    // printf("%s", response.c_str());

    // TODO: handle wrong format
    // Parse the reponse to get http code and body
    // Find the https code first

    std::string code;
    std::string body;
    try {
        code = response.substr(9, 3);
        int div_idx = response.find("\r\n\r\n");
        body = response.substr(div_idx + 4);
    } catch (std::exception& ex) {

    }

    fprintf(stderr, "%s\n", code.c_str());
    fprintf(stderr, "%s\n", body.c_str());

    if (code != "200") {
        return 1;
    } else {
        return 0;
    }
}

int rand_num(int l, int r) {
    std::random_device rd; // obtain a random number from hardware
    std::mt19937 gen(rd()); // seed the generator
    std::uniform_int_distribution<> distr(l, r); // define the range
    return distr(gen);
}

std::string rand_string() {
    std::string str;
    char c[1];
    int len = rand_num(1, 3000);
    for (int i = 0; i < len; i++) {
        c[0] = (char)(rand_num(0, 127));
        str.append(std::string(c));
    }
    // printf("%s", str.c_str());

    return str;
}


int main(int argc, char const* argv[]) {
    srand(time(NULL));
    Info info;
    info.action = (Action)(rand_num(0, 8));
    printf("%d", info.action);
    info.cert_path = "./addleness_certificate.pem";
    std::string priv = "./addleness_private_key.pem";

    std::string bad_string = rand_string();
    exit(client_send(info, priv, bad_string));
}
