#ifndef CMS_HPP
#define CMS_HPP

int cms_enc(std::string& recipient_cert, std::string& msg_path);

int cms_sign(std::string& cert_path, std::string& pri_key_path, BIO* msg);
int cms_verify(std::string& signer_cert, std::string& ca_chain_path, int chain_depth)

#endif
