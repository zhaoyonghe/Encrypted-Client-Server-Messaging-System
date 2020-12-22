#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sstream>

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#define RSA_KEY_BITS (4096)

#define REQ_DN_C "SE"
#define REQ_DN_ST ""
#define REQ_DN_L ""
#define REQ_DN_O "Example Company"
#define REQ_DN_OU ""
#define REQ_DN_CN "VNF Application"

static void crt_to_pem(X509* crt, uint8_t** crt_bytes, size_t* crt_size);
static void csr_to_pem(X509_REQ* req, uint8_t** req_bytes, size_t* req_size);
static int generate_key_csr(const std::string& username, EVP_PKEY** key, X509_REQ** req);
static int generate_set_random_serial(X509* crt);
static int generate_signed_key_pair(X509_REQ* req, EVP_PKEY* ca_key, X509* ca_crt, EVP_PKEY** key, X509** crt);
static void key_to_pem(EVP_PKEY* key, uint8_t** key_bytes, size_t* key_size);
static int load_ca(const char* ca_key_path, EVP_PKEY** ca_key, const char* ca_crt_path, X509** ca_crt);
static void print_bytes(uint8_t* data, size_t size);

// int main_example(int argc, char **argv)
// {
// 	/* Assumes the CA certificate and CA key is given as arguments. */
// 	if (argc != 3) {
// 		fprintf(stderr, "usage: %s <cakey> <cacert>\n", argv[0]);
// 		return 1;
// 	}

// 	char *ca_key_path = argv[1];
// 	char *ca_crt_path = argv[2];

// 	/* Load CA key and cert. */
// 	EVP_PKEY *ca_key = NULL;
// 	X509 *ca_crt = NULL;
// 	if (!load_ca(ca_key_path, &ca_key, ca_crt_path, &ca_crt)) {
// 		fprintf(stderr, "Failed to load CA certificate and/or key!\n");
// 		return 1;
// 	}

// 	/* Generate keypair and then print it byte-by-byte for demo purposes. */
// 	EVP_PKEY *key = NULL;
// 	X509 *crt = NULL;

// 	int ret = generate_signed_key_pair(ca_key, ca_crt, &key, &crt);
// 	if (!ret) {
// 		fprintf(stderr, "Failed to generate key pair!\n");
// 		return 1;
// 	}
// 	/* Convert key and certificate to PEM format. */
// 	uint8_t *key_bytes = NULL;
// 	uint8_t *crt_bytes = NULL;
// 	size_t key_size = 0;
// 	size_t crt_size = 0;

// 	key_to_pem(key, &key_bytes, &key_size);
// 	crt_to_pem(crt, &crt_bytes, &crt_size);

// 	/* Print key and certificate. */
// 	print_bytes(key_bytes, key_size);
// 	print_bytes(crt_bytes, crt_size);

// 	/* Free stuff. */
// 	EVP_PKEY_free(ca_key);
// 	EVP_PKEY_free(key);
// 	X509_free(ca_crt);
// 	X509_free(crt);
// 	free(key_bytes);
// 	free(crt_bytes);

// 	return 0;
// }

int get_common_name_from_cert(const X509* crt, std::string& out) {
	X509_NAME* name = NULL;
	X509_NAME_ENTRY* entry = NULL;

	if (crt != NULL) {
		name = X509_get_subject_name(crt);
		if (name != NULL) {
			int lastpos = -1;
			lastpos = X509_NAME_get_index_by_NID(name, NID_commonName, lastpos);
			if (lastpos != -1) {
				entry = X509_NAME_get_entry(name, lastpos);
				ASN1_STRING* asn = X509_NAME_ENTRY_get_data(entry);
				unsigned char* common_name;
				ASN1_STRING_to_UTF8(&common_name, asn);
				out = std::string(reinterpret_cast<char const*>(common_name));
			} else {
				return 1;
			}
		} else {
			return 1;
		}
	} else {
		return 1;
	}

	return 0;
}

void crt_to_pem(X509* crt, uint8_t** crt_bytes, size_t* crt_size) {
	/* Convert signed certificate to PEM format. */
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	*crt_size = BIO_pending(bio);
	*crt_bytes = (uint8_t*)malloc(*crt_size + 1);
	BIO_read(bio, *crt_bytes, *crt_size);
	BIO_free_all(bio);
}

void key_to_pem(EVP_PKEY* key, uint8_t** key_bytes, size_t* key_size) {
	/* Convert private key to PEM format. */
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
	*key_size = BIO_pending(bio);
	*key_bytes = (uint8_t*)malloc(*key_size + 1);
	BIO_read(bio, *key_bytes, *key_size);
	BIO_free_all(bio);
}

void csr_to_pem(X509_REQ* req, uint8_t** req_bytes, size_t* req_size) {
	/* Convert certificate signing request to PEM format. */
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio, req);
	*req_size = BIO_pending(bio);
	*req_bytes = (uint8_t*)malloc(*req_size + 1);
	BIO_read(bio, *req_bytes, *req_size);
	BIO_free_all(bio);
}

int generate_signed_key_pair(X509_REQ* req, EVP_PKEY* ca_key, X509* ca_crt, EVP_PKEY** key, X509** crt) {
	/* Generate the private key and corresponding CSR. */
	EVP_PKEY* req_pubkey;

	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt)
		goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt))
		goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2 * 365 * 24 * 3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	// Set extensions of the certificate
	// X509_EXTENSION *ex;
	// X509V3_CTX ctx;
	// X509V3_set_ctx_nodb(&ctx);
	// X509V3_set_ctx(&ctx, ca_crt, *crt, req, NULL, 0);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, (char *)"CA:FALSE")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_netscape_cert_type, (char *)"client, email")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_netscape_comment, (char *)"OpenSSL Generated Client Certificate")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, (char *)"CA:FALSE")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, (char *)"hash")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, (char *)"keyid,issuer")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, (char *)"critical, nonRepudiation, digitalSignature, keyEncipherment")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, (char *)"clientAuth, emailProtection")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	// if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, (char *)"IP:2.2.2.2")))
	// 	goto err;
	// X509_add_ext(*crt, ex, -1);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0)
		goto err;

	X509_REQ_free(req);
	return 1;
err:
	//EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}

int generate_key_csr(const std::string& username, EVP_PKEY** key, X509_REQ** req) {
	*key = NULL;
	*req = NULL;
	RSA* rsa = NULL;
	BIGNUM* e = NULL;
	X509_NAME* name;

	*key = EVP_PKEY_new();
	if (!*key)
		goto err;
	*req = X509_REQ_new();
	if (!*req)
		goto err;
	rsa = RSA_new();
	if (!rsa)
		goto err;
	e = BN_new();
	if (!e)
		goto err;

	BN_set_word(e, 65537);
	if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, e, NULL))
		goto err;
	if (!EVP_PKEY_assign_RSA(*key, rsa))
		goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set the DN of the request. */
	name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)REQ_DN_C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)username.c_str(), -1, -1, 0);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256()))
		goto err;

	BN_free(e);

	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	RSA_free(rsa);
	BN_free(e);
	return 0;
}

int generate_set_random_serial(X509* crt) {
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1)
		return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM* bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER* serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

int load_ca(const char* ca_key_path, EVP_PKEY** ca_key, const char* ca_crt_path, X509** ca_crt) {
	BIO* bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path))
		goto err;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt)
		goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_key_path))
		goto err;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!ca_key)
		goto err;
	BIO_free_all(bio);
	return 1;
err:
	BIO_free_all(bio);
	X509_free(*ca_crt);
	EVP_PKEY_free(*ca_key);
	return 0;
}

void print_bytes(uint8_t* data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%c", data[i]);
	}
}

// Generate and save key and csr. Return csr for get_cert usage
int generate_key_and_csr(const std::string& username, std::string& key_out, std::string& csr_out) {
	// Generate key and csr
	X509_REQ* req = NULL;
	EVP_PKEY* key = NULL;
	generate_key_csr(username, &key, &req);

	// Convert key and csr to pem
	uint8_t* key_bytes = NULL;
	uint8_t* csr_bytes = NULL;
	size_t key_size = 0;
	size_t csr_size = 0;
	key_to_pem(key, &key_bytes, &key_size);
	csr_to_pem(req, &csr_bytes, &csr_size);

	std::ostringstream csr_pem_stream;
	csr_pem_stream << csr_bytes;
	csr_out = csr_pem_stream.str();

	std::ostringstream key_pem_stream;
	key_pem_stream << key_bytes;
	key_out = key_pem_stream.str();

	// Free stuff
	EVP_PKEY_free(key);
	X509_REQ_free(req);
	free(key_bytes);
	free(csr_bytes);

	return 0;
}