#include "client.cpp"

int main()
{
    Info info;
    info.action = recvmsg;

    client_send(info);
}