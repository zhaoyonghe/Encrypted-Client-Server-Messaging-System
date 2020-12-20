#include <string>
#include "info.hpp"

#ifndef CLIENT_HPP
#define CLIENT_HPP

int client_send(Info& info, std::string& code, std::string& body, std::string& private_key_path);

#endif