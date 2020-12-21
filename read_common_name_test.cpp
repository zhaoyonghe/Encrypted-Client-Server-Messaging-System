#include <stdint.h>
#include <stdio.h>
#include <string>

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "my.hpp"

int get_common_name(X509 *crt, std::string &out)
{
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *entry = NULL;

    if (crt != NULL)
    {
        name = X509_get_subject_name(crt);
        if (name != NULL)
        {
            int lastpos = -1;
            lastpos = X509_NAME_get_index_by_NID(name, NID_commonName, lastpos);
            if (lastpos != -1)
            {
                entry = X509_NAME_get_entry(name, lastpos);
                ASN1_STRING *asn = X509_NAME_ENTRY_get_data(entry);
                unsigned char *common_name;
                ASN1_STRING_to_UTF8(&common_name, asn);
                out = std::string(reinterpret_cast<char const *>(common_name));
            }
            else
            {
                return 1;
            }
        }
        else
        {
            return 1;
        }
    }
    else
    {
        return 1;
    }

    return 0;
}

int main()
{
    std::string crt_string = "-----BEGIN CERTIFICATE-----\n\
MIIEXzCCA0egAwIBAgIUErJuphL7xiZeO7atcEb6unnuhKYwDQYJKoZIhvcNAQEL\n\
BQAwgZcxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMR8wHQYDVQQKDBZZ\n\
b25naGUgWmhhbyBDQSBTZXJ2aWNlMQswCQYDVQQLDAJJVDEkMCIGA1UEAwwbWW9u\n\
Z2hlIFpoYW8gaW50ZXJtZWRpYXRlIENBMSIwIAYJKoZIhvcNAQkBFhN5ejM2ODdA\n\
Y29sdW1iaWEuZWR1MB4XDTIwMTIyMTAwNDIwNFoXDTIyMTIyMTAwNDIwNFowOzEL\n\
MAkGA1UEBhMCU0UxGDAWBgNVBAoMD0V4YW1wbGUgQ29tcGFueTESMBAGA1UEAwwJ\n\
YWRkbGVuZXNzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzEB798GR\n\
JEPDMo8me91Ehwd1DUTZujv1Y0e87XfmmWU7+nljqz2VyB3sw8esOjY0OSdsqF1A\n\
XDtN70OEzzRlleKk6yCYufMlqjds9bEZuS2OlYY7bDL9rtnWuHBlXyFINXnBH1p7\n\
s2r9wiby5/t0tATjV+cym4lRg3SaCBVhopJM6obRc34xLi/aOUxCgBT7UzbGwl+Z\n\
PHkJf++yN7IpsWq28PCF0MQ+3wDXodLBfkUCPPUYbqLEjONDKqovv0IMxKnZwsra\n\
0AW2qD3Acd90cWYjKBMQG3trUrTv/xj+SVXGfPj6HDsNnNGqHwHVjH2zTHGjEcSa\n\
SChLx+feVRz9M4h83SeL3yv4ncfJcSwsJrTuGR7AZeydNt4UPIdIIGIrJLhhW3eZ\n\
lxstVy/CeZPHC0CZ3mJLG8b4GoR1IndVZPX1QEGHDhnwSeYxuAMM+eiO2lIFmane\n\
CRM+En7Zkhzv1ho5XDx4WOlvfobu4Xcq9cuTN3LMAKCW/sDa808wezq7xYOYA1oa\n\
lR0rDG0I+feCR3MXYyicmBaKf0Gbk45UWoL4AdzEsGvpV87FbcOoR7mKGKUd3J4e\n\
F07Q1H44SAXd9IoFBOjKewK6fGpROPkxIQZXTxsHa6NZ1Uk7jCycl3hSEEUF20/v\n\
mdNXHXfrhk2QlTsbYboFBQ6Rh1M+ayb3UQECAwEAATANBgkqhkiG9w0BAQsFAAOC\n\
AQEAaACGi9XN9uZIUhXakaC9Tfs1dP5T61z23sN3LEXHWSZ8ZdQmKVMp1lNUH8iH\n\
V/7GL0a9r192tXkgfTMwZp/8negYaL5zInPpWZddSv6COnP7WzTme8zWkvCtyxqD\n\
nkTlwDzK8kcw624GuTM40PHknfCRFmjhJwJaInb5hPwnd5+OpK4ZNzLn/8vZ3h/9\n\
EtsOh71rEx4RQdh7IA+X4G4y/hfBB7W9obOUU5fIy0jET7qayFPze+pCNcvxrUM9\n\
osupGL1oa8uwgQ+o43FKfgryGTagl63LlcbRPs4+SYmhUH5g1s9kPMlJiyLi3yCQ\n\
o5TMS0/w/nqkGzmZUslcqrRLuw==\n\
-----END CERTIFICATE-----";

    // Get common name from certificate
    X509 *crt = NULL;
    std::string common_name;

    auto crt_bio = my::UniquePtr<BIO>(BIO_new_mem_buf(crt_string.c_str(), crt_string.length()));
    crt = PEM_read_bio_X509(crt_bio.get(), NULL, NULL, NULL);
    get_common_name(crt, common_name);
    printf("common name:%s", common_name.c_str());

    // Free stuff
    X509_free(crt);

    return 0;
}