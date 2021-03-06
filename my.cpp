#include "my.hpp"

namespace my {
    std::map<std::string, std::string> http_code = {
        {"200", "OK"},
        {"400", "Bad Request"},
        {"401", "Unauthorized"},
        {"406", "Not Acceptable"}
    };

    my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper) {
        BIO_push(upper.get(), lower.release());
        return upper;
    }

    [[noreturn]] void print_errors_and_exit(const char* message) {
        fprintf(stderr, "%s\n", message);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    [[noreturn]] void print_errors_and_throw(const char* message) {
        my::StringBIO bio;
        ERR_print_errors(bio.bio());
        throw std::runtime_error(std::string(message) + "\n" + std::move(bio).str());
    }

    std::string receive_some_data(BIO* bio) {
        char buffer[1024];
        int len = BIO_read(bio, buffer, sizeof(buffer));
        if (len < 0) {
            my::print_errors_and_throw("error in BIO_read");
        } else if (len > 0) {
            return std::string(buffer, len);
        } else if (BIO_should_retry(bio)) {
            return receive_some_data(bio);
        } else {
            my::print_errors_and_throw("empty BIO_read");
        }
    }

    std::vector<std::string> split_headers(const std::string& text) {
        std::vector<std::string> lines;
        const char* start = text.c_str();
        while (const char* end = strstr(start, "\r\n")) {
            lines.push_back(std::string(start, end));
            start = end + 2;
        }
        return lines;
    }

    std::string receive_http_message(BIO* bio) {
        std::string headers = my::receive_some_data(bio);
        char* end_of_headers = strstr(&headers[0], "\r\n\r\n");
        while (end_of_headers == nullptr) {
            headers += my::receive_some_data(bio);
            end_of_headers = strstr(&headers[0], "\r\n\r\n");
        }
        std::string body = std::string(end_of_headers + 4, &headers[headers.size()]);
        headers.resize(end_of_headers + 2 - &headers[0]);
        size_t content_length = 0;
        for (const std::string& line : my::split_headers(headers)) {
            if (const char* colon = strchr(line.c_str(), ':')) {
                auto header_name = std::string(&line[0], colon);
                if (header_name == "Content-Length") {
                    content_length = std::stoul(colon + 1);
                }
            }
        }
        while (body.size() < content_length) {
            body += my::receive_some_data(bio);
        }
        return headers + "\r\n" + body;
    }

    void send_http_request(BIO* bio, const std::string& line, const std::string& host) {
        std::string request = line + "\r\n";
        request += "Host: " + host + "\r\n";
        request += "\r\n";

        BIO_write(bio, request.data(), request.size());
        BIO_flush(bio);
    }

    void send_http_post(BIO* bio, const std::string& line, const std::string& host, const std::string& body) {
        std::string post = line + "\r\n";
        post += "Host: " + host + "\r\n";
        post += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        post += "\r\n";

        BIO_write(bio, post.data(), post.size());
        BIO_write(bio, body.data(), body.size());
        BIO_flush(bio);
    }

    void send_http_response(BIO* bio, std::string& code, const std::string& body) {
        // If code doesn't exist in map, use 400
        if (http_code.find(code) == http_code.end()) {
            code = "400";
        }

        std::string response = "HTTP/1.1 " + code + " " + http_code[code] + "\r\n";
        response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        response += "\r\n";

        BIO_write(bio, response.data(), response.size());
        BIO_write(bio, body.data(), body.size());
        BIO_flush(bio);
    }

    my::UniquePtr<BIO> accept_new_tcp_connection(BIO* accept_bio) {
        if (BIO_do_accept(accept_bio) <= 0) {
            return nullptr;
        }
        return my::UniquePtr<BIO>(BIO_pop(accept_bio));
    }

    SSL* get_ssl(BIO* bio) {
        SSL* ssl = nullptr;
        BIO_get_ssl(bio, &ssl);
        if (ssl == nullptr) {
            my::print_errors_and_exit("Error in BIO_get_ssl");
        }
        return ssl;
    }

    void verify_the_certificate(SSL* ssl, const std::string& expected_hostname) {
        int err = SSL_get_verify_result(ssl);
        if (err != X509_V_OK) {
            const char* message = X509_verify_cert_error_string(err);
            fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
            SSL_shutdown(ssl);
            exit(1);
        }
        X509* cert = SSL_get_peer_certificate(ssl);
        if (cert == nullptr) {
            fprintf(stderr, "No certificate was presented by the server\n");
            SSL_shutdown(ssl);
            exit(1);
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1) {
            fprintf(stderr, "Certificate verification error: X509_check_host\n");
            exit(1);
        }
#else
        // X509_check_host is called automatically during verification,
        // because we set it up in main().
        (void)expected_hostname;
#endif
    }

    bool is_valid_safe_username(const std::string& str) {
        if (str.empty() || str.length() > 30) {
            return false;
        }

        // Check incrementally that all characters are alphabetical
        for (char const& c : str) {
            if (!std::isalpha(c)) {
                return false;
            }
        }

        return true;
    }

    std::string load_file_to_string(const std::string& filename) {
        std::ifstream t(filename);
        std::stringstream stream;
        stream << t.rdbuf();
        t.close();
        return stream.str();
    }

    void delete_file(const std::string& filename) {
        remove(filename.c_str());
    }

} // namespace my