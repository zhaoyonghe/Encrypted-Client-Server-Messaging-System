#include "client.hpp"
#include "info.hpp"
#include "cms.hpp"
#include "my.hpp"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: ./recvmsg.out <certpath> <privkeypath>\n");
        exit(1);
    }

    Info info;
    info.action = recvmsg;
    info.cert_path = std::string(argv[1]);
    std::string private_key_path = std::string(argv[2]);

    std::string code, body;

    try {
        client_send(info, code, body, private_key_path);
    } catch(...) {
        fprintf(stderr, "Failed to get response from server. Please check your input and the liveness of the server.\n");
        exit(1);
    }

    // printf("[%s] [%s]\n", code.c_str(), body.c_str());

    // printf("(%s) (%s)\n", enc_sign_msg.c_str(), signer_cert.c_str());
    if (code != "200") {
        fprintf(stderr, "Error from server: %s.\n", body.c_str());
        exit(1);
    }

    int div_idx = body.find("****div****");
    if (div_idx == std::string::npos) {
        fprintf(stderr, "Invalid server response format.\n");
        exit(1);
    }
    std::string enc_sign_msg = body.substr(0, div_idx);
    std::string signer_cert = body.substr(div_idx + 11);

    my::StringBIO enc_msg;
    //if (cms_verify("", "./certs/container/intermediate_ca/certs/ca-chain.cert.pem", 2, enc_sign_msg, NULL)) {
    if (cms_verify(signer_cert, "./certs/container/intermediate_ca/certs/ca-chain.cert.pem", 2, enc_sign_msg, enc_msg.bio())) {
        exit(1);
    }
    if (cms_dec(info.cert_path, private_key_path, std::move(enc_msg).str(), true)) {
        exit(1);
    }

    fprintf(stdout, "\n\n========================================================================\n");
    fprintf(stdout, "Verified the identity of the sender and decrypted the message successfully, see above.\n");
}