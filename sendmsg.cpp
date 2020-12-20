#include "client.hpp"
#include "my.hpp"
#include "cms.hpp"

#include <fstream>
#include <iostream>

int main(int argc, char* argv[]) {
    Info info;
    info.action = sendmsg;

    if (argc < 5) {
        fprintf(stderr, "Usage: sendmsg <certpath> <privkeypath> <msgpath> <receipient>+");
        exit(1);
    }

    info.cert_path = std::string(argv[1]);
    std::string priv_key_path(argv[2]);
    std::string msg_path(argv[3]);
    for (int i = 4; i < argc; i++) {
        // =============================================
        // Try to get the recipient's certificate
        // =============================================
        info.stage = get_recipient_cert;
        info.recipient = std::string(argv[i]);
        std::string code, body;
        client_send(info, code, body, priv_key_path);

        printf("[%s] [%s]", code.c_str(), body.c_str());

        if (body.empty()) {
            // TODO: or distinguish it by code 
            printf("Cannot get the certificate of user %s, so message cannot be sent.\n", info.recipient.c_str());
            continue;
        }

        // =============================================
        // Encrypt, sign and send the message
        // =============================================
        info.stage = send_encrypted_signed_message;
        my::StringBIO msg_bio;
        if (cms_enc(body, msg_path) || cms_sign(info.cert_path, priv_key_path, msg_bio.bio())) {
            continue;
        }
        info.encrypted_signed_message = std::move(msg_bio).str();

        client_send(info, code, body, priv_key_path);

        printf("[%s] [%s]", code.c_str(), body.c_str());

    }
}