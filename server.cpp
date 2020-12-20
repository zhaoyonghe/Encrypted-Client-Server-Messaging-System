#include <memory>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <fstream>

#include "client.cpp"
#include "openssl-sign-by-ca-master/openssl1.1/main.c"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int handle_getcert(std::string &response, std::string &ca_cert_path, std::string &ca_key_path, std::string &csr_string);

int main()
{
    std::string ca_cert_path = "./certs/container/intermediate_ca/certs/intermediate_ca.cert.pem";
    std::string ca_key_path = "./certs/container/intermediate_ca/private/intermediate_ca.key.pem";
    std::string msg_server_cert_path = "./certs/container/intermediate_ca/certs/msg_server.cert.pem";
    std::string msg_server_key_path = "./certs/container/intermediate_ca/private/msg_server.key.pem";
    std::string input = "-----BEGIN CERTIFICATE REQUEST-----\n\
MIIC+TCCAeECAQAwgbMxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRow\n\
GAYDVQQHDBFDaGFveWFuZyBEaXN0cmljdDEfMB0GA1UECgwWWW9uZ2hlIFpoYW8g\n\
Q0EgU2VydmljZTELMAkGA1UECwwCSVQxJDAiBgNVBAMMG1lvbmdoZSBaaGFvIGlu\n\
dGVybWVkaWF0ZSBDQTEiMCAGCSqGSIb3DQEJARYTeXozNjg3QGNvbHVtYmlhLmVk\n\
dTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK4+crY5jDd3fH3vFvt/\n\
sLbtf5l71w49plx1s4ZYDRon/2CZw8pATe1EBvloICEu1KRiLiEmXs1PEYrzG/3W\n\
eUVqiJQlNnbYGFDyTNBJw7ZJeQ2Es0WRzF8PVNOSx6TUrxEO4SQ2imSmU9NIVfeG\n\
pz2jgGn3C0JMG3VVjsx1lfqFLu90Qpj78NWUajfFliYD9GMcTvEFFY0TMCXD+5z+\n\
yYyjatjvYkkmZXqrst1QBeANnrkXKPGwpvHgz6p0EGW83/9n9zbB5MCjh0y5ayQ8\n\
bdZpk/7qtwnw0YrjkGkSDSbsfVO6BAbpiVIHJ+u0WEwhDSpVW0AhkPvTbHlUuUk1\n\
Fp0CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQA+oRNK4AOZ7kDDdFd2wuoYPE/N\n\
5SqbnhFxsZf70H9iMTRau19y3R5RMCgNLEglMvFK7n6Rgd2Eqwyp3FcaJ4waBj2f\n\
GgxPCyfkQA1sRLZQfrVhEBoD8x0ywIyuIz75+wZ3hX/prEG3ekGpPlVoGaYgLcTk\n\
wyhqRNvdCH7TyEgI4Or/L6lD4ye6Vg5jDwkAuvXUaJYo10BcWEXgZrSF2qBOeY0/\n\
pyn+xq4XK2wyRNg+TAcw/LzRclY85xF4CMKRo/Ltb8shogPSh6dvSQRrFAnB3VqN\n\
N5XExhHkinmClj+W+MoEOtv47xmjz1W1qZn/UzHdSbexQq4O7Ob/ahjF6e0g\n\
-----END CERTIFICATE REQUEST-----";

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ssl_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
    auto ssl_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
    SSL_CTX_set_min_proto_version(ssl_ctx.get(), TLS1_2_VERSION);
#endif

    if (!SSL_CTX_use_certificate_file(ssl_ctx.get(), msg_server_cert_path.c_str(), SSL_FILETYPE_PEM))
    {
        my::print_errors_and_exit("Error loading server certificate");
    }
    if (!SSL_CTX_use_PrivateKey_file(ssl_ctx.get(), msg_server_key_path.c_str(), SSL_FILETYPE_PEM))
    {
        my::print_errors_and_exit("Error loading server private key");
    }
    if (!SSL_CTX_load_verify_locations(ssl_ctx.get(), "./certs/container/intermediate_ca/certs/ca-chain.cert.pem", nullptr))
    {
        my::print_errors_and_exit("Error setting up trust store");
    }

    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept("4399"));
    if (BIO_do_accept(accept_bio.get()) <= 0)
    {
        my::print_errors_and_exit("Error in BIO_do_accept (binding to port 4399)");
    }

    static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
        close(fd);
    };
    signal(SIGINT, [](int) { shutdown_the_socket(); });

    printf("Server running\n");

    std::string header_get = "GET /";
    std::string header_post = "POST /";
    while (auto conn_bio = my::accept_new_tcp_connection(accept_bio.get()))
    {
        conn_bio = std::move(conn_bio) | my::UniquePtr<BIO>(BIO_new_ssl(ssl_ctx.get(), 0));
        try
        {
            std::string request = my::receive_http_message(conn_bio.get());
            printf("Got request:\n");
            printf("%s\n", request.c_str());

            // Parse request here
            std::string action;
            std::size_t get_index = request.find(header_get);
            if (get_index != std::string::npos)
            {
                action = request[get_index + header_get.length()];
            }
            else
            {
                std::size_t post_index = request.find(header_post);
                if (post_index != std::string::npos)
                {
                    action = request[post_index + header_post.length()];
                }
                else
                {
                    my::send_http_response(conn_bio.get(), "no valid action type found\n");
                    continue;
                }
            }

            // Display action type
            int action_num = std::stoi(action, nullptr, 10);
            std::string response;
            std::string action_string;
            switch (action_num)
            {
            case getcert:
                handle_getcert(response, ca_cert_path, ca_key_path, input);
                action_string = "getcert";
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
        }
        catch (const std::exception &ex)
        {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
    }
    printf("\nClean exit!\n");
}

// Simply sign a new certificate for client and send it to client
// TODO: How to specify configuration?
int handle_getcert(std::string &response, std::string &ca_cert_path, std::string &ca_key_path, std::string &csr_string)
{
    // Load CA key and cert.
    EVP_PKEY *ca_key = NULL;
    X509 *ca_crt = NULL;
    if (!load_ca(ca_key_path.c_str(), &ca_key, ca_cert_path.c_str(), &ca_crt))
    {
        printf("Failed to load CA certificate and/or key!\n");
        return 1;
    }

    // Load certificate signing request
    X509_REQ *csr = NULL;
    auto csr_bio = my::UniquePtr<BIO>(BIO_new_mem_buf(csr_string.c_str(), csr_string.length()));
    csr = PEM_read_bio_X509_REQ(csr_bio.get(), NULL, NULL, NULL);

    // Generate keypair and then print it byte-by-byte for demo purposes.
    EVP_PKEY *key = NULL;
    X509 *crt = NULL;
    int ret = generate_signed_key_pair(csr, ca_key, ca_crt, &key, &crt);
    if (!ret)
    {
        printf("Failed to generate key pair!\n");
        return 1;
    }

    // Convert key and certificate to PEM format.
    // uint8_t *key_bytes = NULL;
    // size_t key_size = 0;
    // key_to_pem(key, &key_bytes, &key_size);
    // print_bytes(key_bytes, key_size);

    uint8_t *crt_bytes = NULL;
    size_t crt_size = 0;
    crt_to_pem(crt, &crt_bytes, &crt_size);
    print_bytes(crt_bytes, crt_size);

    // Save signed certificate
    std::ofstream certificate_pem_file("./certs/server_signed_certificate.pem");
    certificate_pem_file << crt_bytes;
    certificate_pem_file.close();

    // Free stuff.
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(key);
    X509_free(ca_crt);
    X509_free(crt);
    X509_REQ_free(csr);
    //free(key_bytes);
    free(crt_bytes);

    return 0;
}
