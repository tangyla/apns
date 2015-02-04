#include <cstdlib>
#include <cstdio>
#include <apns/apns.h>

using namespace std;

int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    const char* passwd = reinterpret_cast<const char *>(userdata);
    strcpy(buf, passwd);
    return strlen(passwd);
}

int main(int argc, char** argv) {
    InitSSLLibrary();

    try {
        string host("gateway.push.apple.com");
        int port(2195);

        string cert("/home/tangyla/work/iospush/cert/product/PushCert.pem");
        string key("/home/tangyla/work/iospush/cert/product/PushKey.pem");
        string passwd("tuxiaobaoIOS");
        Apns apns(host, port, cert, key, pem_passwd_cb, const_cast<char *>(passwd.c_str()));

        string token("4fa734bfd0d6f579cb5cdd7214f8b1ff57ae4da828577662659d77d904052132");
        string body("Hello World!");
        apns.PushMessage(token, body);
    }
    catch (std::exception& ex) {
        fprintf(stderr, "Exception: [%s].\n", ex.what());
    }

    CloseSSLibrary();

    return EXIT_SUCCESS;
}