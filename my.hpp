#ifndef MY_HPP
#define MY_HPP

#include <memory>
#include <stdarg.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <fstream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

namespace my {
    template <class T>
    struct DeleterOf;
    template <>
    struct DeleterOf<BIO> {
        void operator()(BIO* p) const { BIO_free_all(p); }
    };
    template <>
    struct DeleterOf<BIO_METHOD> {
        void operator()(BIO_METHOD* p) const { BIO_meth_free(p); }
    };
    template <>
    struct DeleterOf<SSL_CTX> {
        void operator()(SSL_CTX* p) const { SSL_CTX_free(p); }
    };

    template <class OpenSSLType>
    using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

    my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper);

    class StringBIO {
        std::string str_;
        my::UniquePtr<BIO_METHOD> methods_;
        my::UniquePtr<BIO> bio_;

    public:
        StringBIO(StringBIO&&) = delete;
        StringBIO& operator=(StringBIO&&) = delete;

        explicit StringBIO() {
            methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
            if (methods_ == nullptr) {
                throw std::runtime_error("StringBIO: error in BIO_meth_new");
            }
            BIO_meth_set_write(methods_.get(), [](BIO* bio, const char* data, int len) -> int {
                std::string* str = reinterpret_cast<std::string*>(BIO_get_data(bio));
                str->append(data, len);
                return len;
                });
            bio_.reset(BIO_new(methods_.get()));
            if (bio_ == nullptr) {
                throw std::runtime_error("StringBIO: error in BIO_new");
            }
            BIO_set_data(bio_.get(), &str_);
            BIO_set_init(bio_.get(), 1);
        }
        BIO* bio() { return bio_.get(); }
        std::string str()&& { return std::move(str_); }
    };

    [[noreturn]] void print_errors_and_exit(const char* message);

    [[noreturn]] void print_errors_and_throw(const char* message);

    std::string receive_some_data(BIO* bio);

    std::vector<std::string> split_headers(const std::string& text);

    std::string receive_http_message(BIO* bio);

    void send_http_request(BIO* bio, const std::string& line, const std::string& host);

    void send_http_post(BIO* bio, const std::string& line, const std::string& host, const std::string& body);

    void send_http_response(BIO* bio, std::string& code, const std::string& body);

    my::UniquePtr<BIO> accept_new_tcp_connection(BIO* accept_bio);

    SSL* get_ssl(BIO* bio);

    void verify_the_certificate(SSL* ssl, const std::string& expected_hostname);

    bool is_valid_safe_username(const std::string& str);

    std::string load_file_to_string(const std::string& filename);
    void delete_file(const std::string& filename);

} // namespace my

#endif