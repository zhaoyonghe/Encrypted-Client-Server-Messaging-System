#include "client.hpp"
#include "my.hpp"
#include "cms.hpp"
#include "info.hpp"

#include <fstream>
#include <iostream>
#include <string>

// ./sendmsg.out ./addleness_certificate.pem ./addleness_private_key.pem ./play.cpp overrich

int main(int argc, char* argv[]) {

    if (argc < 5) {
        fprintf(stderr, "Usage: sendmsg <certpath> <privkeypath> <msgpath> <receipient>+\n");
        exit(1);
    }

    Info info;
    info.cert_path = std::string(argv[1]);
    std::string priv_key_path(argv[2]);
    std::string msg_path(argv[3]);
    for (int i = 4; i < argc; i++) {
        // =============================================
        // Try to get the recipient's certificate
        // =============================================
        info.action = sendmsg_get_recipient_cert;
        info.recipient = std::string(argv[i]);
        std::string code, body;
        client_send(info, code, body, priv_key_path);

        printf("[%s] [%s]", code.c_str(), body.c_str());

        if (code != "200") {
            printf("Message cannot be sent to %s: %s\n", info.recipient.c_str(), body.c_str());
            continue;
        }

        // =============================================
        // Encrypt, sign and send the message
        // =============================================
        info.action = sendmsg_send_encrypted_signed_message;
        my::StringBIO enc_msg_bio;
        if (cms_enc(body, msg_path, enc_msg_bio.bio())) {
            continue;
        }
        if (cms_sign(info.cert_path, priv_key_path, std::move(enc_msg_bio).str(), NULL)) {
            continue;
        }
        info.encrypted_signed_message = my::load_file_to_string("./tmp/smout.txt");
        printf("fucking[%s]\n", info.encrypted_signed_message.c_str());

        client_send(info, code, body, priv_key_path);

        printf("[%s] [%s]", code.c_str(), body.c_str());

    }
}