#include "client.hpp"
#include "info.hpp"
#include "cms.hpp"
#include "my.hpp"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: recvmsg <certpath> <privkeypath>\n");
        exit(1);
    }

    Info info;
    info.action = recvmsg;
    info.cert_path = std::string(argv[1]);
    std::string private_key_path = std::string(argv[2]);

    std::string code, body;

    client_send(info, code, body, private_key_path);

    printf("[%s] [%s]\n", code.c_str(), body.c_str());

    my::StringBIO enc_msg;
    if (cms_verify("", "./certs/container/intermediate_ca/certs/ca-chain.cert.pem", 2, body, NULL)) {
    //if (cms_verify("", "./certs/container/intermediate_ca/certs/ca-chain.cert.pem", 2, body, enc_msg.bio())) {
        exit(1);
    }
    if (cms_dec(info.cert_path, private_key_path, std::move(enc_msg).str(), true)) {
        exit(1);
    }
}