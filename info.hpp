#ifndef INFO_HPP
#define INFO_HPP

#include <string>
#include <vector>
#include <cstring>

// Represent all possible actions.
enum Action {
    getcert,
    changepw,
    sendmsg_get_recipient_cert,
    sendmsg_send_encrypted_signed_message,
    recvmsg,
    unsupport,
};

// Represent info sent by the client to the server.
class Info {
public:
    const static int ENCODED_FIELD_NUM = 6;
    Action action;
    std::string username;
    std::string password;
    std::string new_password;
    std::string csr;
    std::string recipient;
    std::string encrypted_signed_message;
    std::string cert_path;

    Info() = default;

    void print_info() {
        printf("action: %d\n", action);
        printf("username: [%s]\n", username.c_str());
        printf("password: [%s]\n", password.c_str());
        printf("new_password: [%s]\n", new_password.c_str());
        printf("csr: [%s]\n", csr.c_str());
        printf("cert_path: [%s]\n", cert_path.c_str());
    }

    std::string to_string() {
        std::string info_str;
        info_str.append(username).append(password).append(new_password).append(csr).append(recipient).append(encrypted_signed_message);

        int break_down = username.length();
        info_str.append("|").append(std::to_string(break_down));
        break_down += password.length();
        info_str.append(",").append(std::to_string(break_down));
        break_down += new_password.length();
        info_str.append(",").append(std::to_string(break_down));
        break_down += csr.length();
        info_str.append(",").append(std::to_string(break_down));
        break_down += recipient.length();
        info_str.append(",").append(std::to_string(break_down));
        break_down += encrypted_signed_message.length();
        info_str.append(",").append(std::to_string(break_down));
        info_str.append(",");
        return info_str;
    }

    bool from_string(std::string& info_string) {
        int divider_pos = info_string.find_last_of('|');
        if (divider_pos == std::string::npos) {
            return false;
        }
        printf("%d!!\n", divider_pos);

        std::vector<int> positions = split_positions(info_string.substr(divider_pos + 1));

        printf("%d %d %d %d %zu\n", positions[0], positions[1], positions[2], positions[3], positions.size());

        if (positions.size() != ENCODED_FIELD_NUM) {
            return false;
        }

        username = info_string.substr(0, positions[0] - 0);
        password = info_string.substr(positions[0], positions[1] - positions[0]);
        new_password = info_string.substr(positions[1], positions[2] - positions[1]);
        csr = info_string.substr(positions[2], positions[3] - positions[2]);
        recipient = info_string.substr(positions[3], positions[4] - positions[3]);
        encrypted_signed_message = info_string.substr(positions[4], positions[5] - positions[4]);

        return true;
    }
private:
    std::vector<int> split_positions(const std::string& text) {
        std::vector<int> positions;
        const char* start = text.c_str();
        while (const char* end = strstr(start, ",")) {
            positions.push_back(std::stoi(std::string(start, end)));
            start = end + 1;
            if (positions.size() > ENCODED_FIELD_NUM) {
                // too many fields
                return positions;
            }
        }
        return positions;
    }
};

#endif