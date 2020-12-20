#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

#include <fstream>
#include <iostream>
#include <sstream>

#include "my.hpp"
#include "cms.hpp"

// encrypt the message in msg_path and write to encrypted_msg.txt
int cms_enc(std::string& recipient_cert, std::string& msg_path) {
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
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

    out = BIO_new_file("encrypted_msg.txt", "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
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

int cms_dec(std::string& cert_path, std::string& pri_key_path, BIO* encrypted_msg) {
    BIO *out = NULL, *cbio = NULL, *kbio = NULL;
    X509 *mcert = NULL;
    EVP_PKEY *mkey = NULL;
    CMS_ContentInfo *cms = NULL;
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
    cms = SMIME_read_CMS(encrypted_msg, NULL);
    if (!cms)
        goto err;

    out = BIO_new_file("decout.txt", "w");
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
    //BIO_free(in);
    BIO_free(out);
    BIO_free(cbio);
    BIO_free(kbio);
    return ret;
}

int cms_sign(std::string& cert_path, std::string& pri_key_path, BIO* msg) {
    BIO *in = NULL, *out = NULL, *cbio = NULL, *kbio = NULL;
    X509 *mcert = NULL;
    EVP_PKEY *mkey = NULL;
    CMS_ContentInfo *cms = NULL;
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
    in = BIO_new_file("encrypted_msg.txt", "r");

    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(mcert, mkey, NULL, in, flags);

    if (!cms)
        goto err;

    out = BIO_new_file("smout.txt", "w");
    if (!out)
        goto err;

    if (!(flags & CMS_STREAM))
        BIO_reset(in);

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;
    if (!SMIME_write_CMS(msg, cms, in, flags))
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

int cms_verify(std::string& signer_cert, std::string& ca_chain_path)
{
    BIO *in = NULL, *out = NULL, *sbio = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    X509 *scert = NULL;
    STACK_OF(X509) *signers = NULL;
    CMS_ContentInfo *cms = NULL;

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
    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!cacert)
        goto err;
    if (!X509_STORE_add_cert(st, cacert))
        goto err;
    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!cacert)
        goto err;
    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    /* Open message being verified */

    in = BIO_new_file("smout.txt", "r");

    if (!in)
        goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file("smver.txt", "w");
    if (!out)
        goto err;

    if (!CMS_verify(cms, signers, st, cont, out, 0)) {
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
    X509_free(cacert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    BIO_free(sbio);
    return ret;
}


// int main() {
//     std::ifstream r("./certs/container/intermediate_ca/certs/msg_server.cert.pem");
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

//     cms_enc(recipient_cert, msg_path);
//     cms_sign(my_cert_path, my_priv_key_path);
//     cms_verify(my_cert, ca_chain_path);

// }


