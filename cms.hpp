int cms_enc(std::string& recipient_cert, std::string& msg_path);

int cms_sign(std::string& cert_path, std::string& pri_key_path, BIO* msg);
