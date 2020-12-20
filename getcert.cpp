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

    // TODO: create csr
    info.csr = "-----BEGIN CERTIFICATE REQUEST-----\n\
MIIC3DCCAcQCAQAwgZYxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdUaWFuamluMRgw\n\
FgYDVQQHDA9OYW5rYWkgRGlzdHJpY3QxGDAWBgNVBAoMD05hbmthaSBTb2Z0d2Fy\n\
ZTELMAkGA1UECwwCSVQxEDAOBgNVBAMMB3N0dWRlbnQxIjAgBgkqhkiG9w0BCQEW\n\
E2lhbWFzdHVkZW50QGFiYy5lZHUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
AoIBAQC5gdFjZ3H6Bdku5hkJt7CJ+m/KKkN274zbsztxCrcznMAm3QRsI+/mYEnb\n\
Lqm7HhKWTsbhRWp51lljVudeZTe2HpW6sqJeuBEK35v9y/eUZoC7A4Q5/SMIRvDg\n\
ItUdYES/FG+F1bPZ1bAP8M6rI9ZdTxbquxiqFy9aFIY+3NnPjiIPixfEJpUqYuRP\n\
nsuoHprKpyGc4aGTa4ZhOY8Q8zIs6/Vu7EYm9oNGphgt61lyVwgtjIdqCAZizNcD\n\
TTwDDLDFn8AezMxpUFssk1iIgnfQhT5QF6YFXhzqrgSixm9LKGLQ++GgpI7ooP8p\n\
5Kaa0HQEHCwhUCPalR9bFxCEZ1vXAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEA\n\
JwWem2iTHyyj53NMXtN61oLKlVVHoW1U1g20G1TPCuYa3sjFR8zUMgwcYbcL53ZT\n\
Zjs8EbnyC+XtYduP6kFjf6A8caw5My2sSB74+NPFTPncY5CYTXFh4ast9JlNTdtt\n\
kgdpT/z2fo2muE5IkpxWk9OoUOm0cTss80XGG0YFsPKVzSQld+ot7uOFdxr/NMSf\n\
RcMnSflUuKOnJgcR7SwLFEdlGAe2S8Eq7PkuogzRgg+3aivx2dBeLg8QdC1GW3oB\n\
mujoM8gnDn+lwfqFEkd5+F+GfcoddJL7TOdzATr9Bilao8hmdt7NjlzWhmy12sCF\n\
88cXgEyj2FHdlyvVr1m65A==\n\
-----END CERTIFICATE REQUEST-----\n\
";

    info.print_info();

    client_send(info);
}