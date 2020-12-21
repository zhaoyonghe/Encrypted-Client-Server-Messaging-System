#ifndef CMS_HPP
#define CMS_HPP

#include <string>
#include <openssl/bio.h>

int cms_enc(const std::string& recipient_cert, const std::string& msg_path, BIO* enc_msg);
int cms_dec(const std::string& cert_path, const std::string& pri_key_path, const std::string& enc_msg, const bool display);
int cms_sign(const std::string& cert_path, const std::string& pri_key_path, const std::string& enc_msg, BIO* enc_sign_msg);
int cms_verify(const std::string& signer_cert, const std::string& ca_chain_path, int chain_depth, const std::string& enc_sign_msg, BIO* enc_msg);

#endif
