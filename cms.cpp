#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

#include <fstream>
#include <iostream>
#include <sstream>

#include "cms.hpp"

// encrypt the message in msg_path and write to enc_msg.txt
int cms_enc(const std::string& recipient_cert, const std::string& msg_path, BIO* enc_msg) {
    BIO* in = NULL, * out = NULL, * tbio = NULL;
    X509* rcert = NULL;
    STACK_OF(X509)* recips = NULL;
    CMS_ContentInfo* cms = NULL;
    int ret = 1;

    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = BIO_new_mem_buf(recipient_cert.c_str(), recipient_cert.length());

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /*
     * sk_X509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */
    in = BIO_new_file(msg_path.c_str(), "r");

    if (!in)
        goto err;

    /* encrypt content */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
    if (!cms)
        goto err;

    if (enc_msg == NULL) {
        out = BIO_new_file("./tmp/enc_msg.txt", "w");
        if (!out)
            goto err;
        enc_msg = out;
    }

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(enc_msg, cms, in, flags))
        goto err;

    ret = 0;

err:

    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}

int cms_dec(const std::string& cert_path, const std::string& pri_key_path, const std::string& enc_msg, const bool display) {
    BIO *in = NULL, *out = NULL, * cbio = NULL, * kbio = NULL;
    X509* mcert = NULL;
    EVP_PKEY* mkey = NULL;
    CMS_ContentInfo* cms = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in my certificate and private key */
    cbio = BIO_new_file(cert_path.c_str(), "r");
    if (!cbio)
        goto err;
    mcert = PEM_read_bio_X509(cbio, NULL, 0, NULL);

    kbio = BIO_new_file(pri_key_path.c_str(), "r");
    if (!kbio)
        goto err;
    mkey = PEM_read_bio_PrivateKey(kbio, NULL, 0, NULL);

    if (!mcert || !mkey)
        goto err;

    /* Parse message */
    if (enc_msg.empty()) {
        in = BIO_new_file("./tmp/smver.txt", "r");
    } else {
        in = BIO_new_mem_buf(enc_msg.c_str(), enc_msg.length());
    }
    
    cms = SMIME_read_CMS(in, NULL);
    if (!cms)
        goto err;

    if (display) {
        out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
    } else {
        out = BIO_new_file("./tmp/decout.txt", "w");
    }
    
    if (!out)
        goto err;

    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, mkey, mcert, NULL, out, 0))
        goto err;

    ret = 0;

err:

    if (ret) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(mcert);
    EVP_PKEY_free(mkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(cbio);
    BIO_free(kbio);
    return ret;
}

int cms_sign(const std::string& cert_path, const std::string& pri_key_path, const std::string& enc_msg, BIO* enc_sign_msg) {
    BIO* in = NULL, * out = NULL, * cbio = NULL, * kbio = NULL;
    X509* mcert = NULL;
    EVP_PKEY* mkey = NULL;
    CMS_ContentInfo* cms = NULL;
    int ret = 1;

    /*
     * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
     * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
     * non-detached set CMS_STREAM
     */
    int flags = CMS_DETACHED | CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in my certificate and private key */
    cbio = BIO_new_file(cert_path.c_str(), "r");
    if (!cbio)
        goto err;
    mcert = PEM_read_bio_X509(cbio, NULL, 0, NULL);

    kbio = BIO_new_file(pri_key_path.c_str(), "r");
    if (!kbio)
        goto err;
    mkey = PEM_read_bio_PrivateKey(kbio, NULL, 0, NULL);

    if (!mcert || !mkey)
        goto err;

    /* Open content being signed */
    if (enc_msg.empty()) {
        in = BIO_new_file("./tmp/enc_msg.txt", "r");
    } else {
        in = BIO_new_mem_buf(enc_msg.c_str(), enc_msg.length());
    }

    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(mcert, mkey, NULL, in, flags);

    if (!cms)
        goto err;

    if (!(flags & CMS_STREAM))
        BIO_reset(in);

    /* Write out S/MIME message */
    if (enc_sign_msg == NULL) {
        out = BIO_new_file("./tmp/smout.txt", "w");
        if (!out)
            goto err;
        enc_sign_msg = out;
    }

    //out = BIO_new_file("./tmp/cao.txt", "w");
    //out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);

    if (!SMIME_write_CMS(enc_sign_msg, cms, in, flags))
        goto err;

    ret = 0;

err:

    if (ret) {
        fprintf(stderr, "Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(mcert);
    EVP_PKEY_free(mkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(cbio);
    BIO_free(kbio);
    return ret;
}

int cms_verify(const std::string& signer_cert, const std::string& ca_chain_path, int chain_depth, const std::string& enc_sign_msg, BIO* enc_msg) {
    BIO* in = NULL, * out = NULL, * sbio = NULL, * tbio = NULL, * cont = NULL;
    X509_STORE* st = NULL;
    X509* cacert = NULL;
    X509* scert = NULL;
    STACK_OF(X509)* signers = NULL;
    CMS_ContentInfo* cms = NULL;

    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // /* Read in signer certificate */
    // sbio = BIO_new_mem_buf(signer_cert.c_str(), signer_cert.length());
    // if (!sbio)
    //     goto err;
    // scert = PEM_read_bio_X509(sbio, NULL, 0, NULL);
    // if (!scert)
    //     goto err;

    // /* Create signer STACK and add signer cert to it */
    // signers = sk_X509_new_null();
    // if (!signers || !sk_X509_push(signers, scert))
    //     goto err;

    /* Set up trusted CA certificate store */
    st = X509_STORE_new();

    /* Read in CA certificate */
    tbio = BIO_new_file(ca_chain_path.c_str(), "r");
    if (!tbio)
        goto err;

    while (chain_depth > 0) {
        cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
        if (!cacert)
            goto err;
        if (!X509_STORE_add_cert(st, cacert))
            goto err;
        chain_depth--;
    }

    /* Open message being verified */
    if (enc_sign_msg.empty()) {
        in = BIO_new_file("./tmp/smout.txt", "r");
    } else {
        in = BIO_new_mem_buf(enc_sign_msg.c_str(), enc_sign_msg.length());
    }

    if (!in)
        goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);
    if (!cms)
        goto err;

    /* File to output verified content to */
    if (enc_msg == NULL) {
        out = BIO_new_file("./tmp/smver.txt", "w");
        if (!out)
            goto err;
        enc_msg = out;
    }

    if (!CMS_verify(cms, NULL, st, cont, enc_msg, 0)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }

    fprintf(stderr, "Verification Successful\n");

    ret = 0;

err:

    if (ret) {
        fprintf(stderr, "Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    // free all?
    X509_free(cacert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    BIO_free(sbio);
    return ret;
}


// int main() {
//     std::ifstream r("overrich_certificate.pem");
//     std::stringstream rbuffer;
//     rbuffer << r.rdbuf();
//     std::string recipient_cert = rbuffer.str();

//     std::ifstream m("./certs/container/intermediate_ca/certs/client.cert.pem");
//     std::stringstream mbuffer;
//     mbuffer << m.rdbuf();
//     std::string my_cert = mbuffer.str();

//     std::string msg_path = "play.cpp";

//     std::string my_cert_path = "./certs/container/intermediate_ca/certs/client.cert.pem";
//     std::string my_priv_key_path = "./certs/container/intermediate_ca/private/client.key.pem";

//     std::string ca_chain_path = "./certs/container/intermediate_ca/certs/ca-chain.cert.pem";

//     //cms_enc(recipient_cert, "play.cpp", NULL);
//     //cms_sign("addleness_certificate.pem", "addleness_private_key.pem", "", NULL);
//     cms_verify("", ca_chain_path, 2, "", NULL);
//     cms_dec("overrich_certificate.pem", "overrich_private_key.pem", "", true);

// }


