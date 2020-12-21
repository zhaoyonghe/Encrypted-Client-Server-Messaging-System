#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <string>
#include "info.hpp"

int client_send(Info& info, std::string& code, std::string& body, std::string& private_key_path);

#endif