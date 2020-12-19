#include <string>

// Represent all possible actions.
enum Action {
    getcert,
    changepw,
    sendmsg,
    recvmsg
};

// Represent info sent by the client to the server.
class Info {
public:
    Action action;
    std::string username;
    std::string password;
    std::string new_password;
    void print_info() {
        printf("action: %d\n", action);
        printf("username: [%s]\n", username.c_str());
        printf("password: [%s]\n", password.c_str());
        printf("new_password: [%s]\n", new_password.c_str());
    }
};