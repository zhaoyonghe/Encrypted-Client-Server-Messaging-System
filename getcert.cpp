#include "client.hpp"
#include <unistd.h>

int main(int argc, char *argv[]) {
    Info info;
    info.action = getcert;

    if (argc <= 1) {
        fprintf(stderr, "Please enter enough parameters!\n");
        exit(1);
    }

    if (argc > 3) {
        fprintf(stderr, "Too many parameters!");
        exit(1);
    }

    // argc is 2 or 3
    info.username = std::string(argv[1]);
    info.password = (argc == 2) ? std::string(getpass("Input a password:")) : std::string(argv[2]);

    info.print_info();

    client_send(info);
}