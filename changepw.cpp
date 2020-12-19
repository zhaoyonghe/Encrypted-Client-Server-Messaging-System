#include "client.cpp"

int main()
{
    Info info;
    info.action = changepw;

    client_send(info);
}