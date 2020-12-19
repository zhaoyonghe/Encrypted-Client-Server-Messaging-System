#include "client.cpp"

int main()
{
    Info info;
    info.action = getcert;

    client_send(info);
}