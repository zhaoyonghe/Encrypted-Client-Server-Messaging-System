#include "client.cpp"

int main()
{
    Info info;
    info.action = sendmsg;

    client_send(info);
}