#include <cstdlib>
#include <cstdio>

#include "aps.h"

using namespace std;

int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    string passwd("tuxiaobaoIOS");
    strcpy(buf, passwd.c_str());
    return passwd.length();
}

int main(int argc, char** argv) {
    InitSSLLibrary();

    string host("gateway.push.apple.com");
    int port(2195);

    string cert("/home/tangyla/work/iospush/cert/product/PushCert.pem");
    string key("/home/tangyla/work/iospush/cert/product/PushKey.pem");

    string token("4fa734bfd0d6f579cb5cdd7214f8b1ff57ae4da828577662659d77d904052132");
    string body("Hello World!");

    {
        Apns apns(host, port, cert, key, pem_passwd_cb);
        apns.PushMessage(token, body);
    }

    CloseSSLibrary();

    return EXIT_SUCCESS;
}