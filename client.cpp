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
#include "client.hpp"

int client_send(Info& info, std::string& code, std::string& body, std::string& private_key_path) {
    std::string address = "www.msg_server.com";
    char msg_header[50];
    sprintf(msg_header, "POST /%d HTTP/1.1", info.action);

    /* Set up the SSL context */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ssl_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
    auto ssl_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif

    // load self certificate, private key and CA certificate (to verify the identity of the connection peer)
    // TODO: add peer verification for sendmsg
    if (info.action == recvmsg) {
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
        my::send_http_post(ssl_bio.get(), msg_header, "localhost:4399", info.to_string());
    } else if (info.action == sendmsg_get_recipient_cert) {
        my::send_http_post(ssl_bio.get(), msg_header, "localhost:4399", info.recipient);
    } else if (info.action == sendmsg_send_encrypted_signed_message) {
        my::send_http_post(ssl_bio.get(), msg_header, "localhost:4399", info.to_string());
    } else if (info.action == recvmsg) {
        my::send_http_post(ssl_bio.get(), msg_header, "localhost:4399", "");
    } else {
        return 1;
    }

    std::string response = my::receive_http_message(ssl_bio.get());
    printf("%s", response.c_str());

    // TODO: handle wrong format
    // Parse the reponse to get http code and body
    // Find the https code first
    std::string delimiter = " ";
    response.erase(0, response.find(delimiter) + delimiter.length());
    std::string token = response.substr(0, response.find(delimiter));
    response.erase(0, response.find(delimiter) + delimiter.length());
    code = token;

    // Get rid of header and get the body
    delimiter = "\n";
    response.erase(0, response.find(delimiter) + delimiter.length());
    response.erase(0, response.find(delimiter) + delimiter.length());
    response.erase(0, response.find(delimiter) + delimiter.length());
    body = response;

    return 0;
}