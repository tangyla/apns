#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "aps.h"

using namespace std;

void InitSSLLibrary(void) {
    SSL_load_error_strings();
    SSL_library_init();
}

void CloseSSLibrary(void) {
    ERR_free_strings();
}

Apns::Apns(const string& host,
           int port,
           const string& cert_pem,
           const string& key_pem,
           pem_password_cb *cb)
           :ctx_(NULL), ssl_(NULL), sock_(-1) {
    const SSL_METHOD *meth = TLSv1_method();
    ctx_ = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_default_passwd_cb(ctx_, cb);
    SSL_CTX_use_certificate_file(ctx_, cert_pem.c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx_, key_pem.c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_check_private_key(ctx_);

    Conn(host, port);
}

Apns::~Apns(void) {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
    }

    if (sock_ != -1) {
        close(sock_);
    }

    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

void Apns::CheckSSL(void) {
    u_long err;
    char buf[256] = {0};
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "log info: %s\n", buf);
    }
}

void Apns::Conn(const string& host, int port) {
    struct sockaddr_in addr;
    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    hostent * ent = gethostbyname(host.c_str());
    addr.sin_port = htons(port);
    struct in_addr *dest = (struct in_addr*)ent->h_addr_list[0];
    addr.sin_addr.s_addr = inet_addr(inet_ntoa(*dest));

    sock_ = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    connect(sock_, (struct sockaddr*) &addr, sizeof(addr));

    ssl_ = SSL_new(ctx_);
    SSL_set_fd(ssl_, sock_);
    SSL_connect(ssl_);
    CheckSSL();
}


string Apns::Hex2Str(char* buf, size_t len) {
    string ret;
    char ch[2] = { 0 };
    for (size_t i = 0; i < len; ++i) {
        snprintf(ch, sizeof(ch), "%x", buf[i]);
        ret.append(ch);
    }

    return ret;
}

const char* Apns::Str2Hex(const char* str, char* buf, size_t szLen) {
    const char* ret = buf;
    unsigned int ch;
    char tmp[2];
    memset(buf, 0, szLen);
    while (*str != '\0' && szLen--) {
        tmp[0] = *str++;
        tmp[1] = *str++;
        sscanf(tmp, "%x", &ch);
        *buf++ = ch;
    }

    return ret;
}

string Apns::ConstructAps(const string& body, const int badge, const string& sound) {
    char buf[256] = {0};
    snprintf(buf, 
             sizeof(buf),
             "{\"aps\": {\"alert\": \"%s\",\"badge\": %d,\"sound\": \"%s\"}}",
             body.c_str(),
             badge,
             sound.c_str());

    return string(buf);
}

int Apns::PushMessage(const string& deviceToken,
    const string& body,
    const int badge,
    const string& sound) {
    char buf[1024] = { 0 };
    char* ptr = buf;
    char token[32] = { 0 };
    Str2Hex(deviceToken.c_str(), token, sizeof(token));

    // ios app push message info
    // |COMMAND|ID|EXPIRY|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD|
    // |   1   |4 | 4    |    2   | 32  |     2    |  <256 | 字节数
    uint8_t command = 1;
    uint32_t id = static_cast<uint32_t>(time(NULL));
    uint32_t expiry = htonl(id + 86400); // 信息有效期24小时
    uint16_t tokenlen = htons(32);
    string aps = ConstructAps(body, badge, sound);
    uint16_t payloadlen = htons(aps.length());

    memcpy(ptr, &command, sizeof(command));
    ptr += sizeof(command);

    memcpy(ptr, &id, sizeof(id));
    ptr += sizeof(id);

    memcpy(ptr, &expiry, sizeof(expiry));
    ptr += sizeof(expiry);

    memcpy(ptr, &tokenlen, sizeof(tokenlen));
    ptr += sizeof(tokenlen);

    memcpy(ptr, &token, sizeof(token));
    ptr += sizeof(token);

    memcpy(ptr, &payloadlen, sizeof(payloadlen));
    ptr += sizeof(payloadlen);

    memcpy(ptr, aps.c_str(), aps.length());
    ptr += aps.length();

    int ret = SSL_write(ssl_, buf, ptr - buf);
    CheckSSL();

    return ret;
}


void Apns::FeedBack(std::vector<ApnsFeedback>& feedbacks) {
    size_t num = 0;
    char buf[38] = {0};
    while (1) {
        num = SSL_pending(ssl_);
        CheckSSL();
        if (sizeof(buf) >= num) {
            break;
        }

        num = sizeof(buf);
        memset(buf, 0, num);
        SSL_read(ssl_, buf, num);
        char* ptr = buf;

        uint32_t tm;
        memcpy(&tm, ptr, sizeof(tm));
        ptr += sizeof(tm);
        tm = ntohl(tm);

        uint16_t len;
        memcpy(&len, ptr, sizeof(len));
        ptr += sizeof(len);
        len = static_cast<uint16_t>(ntohl(len));

        ApnsFeedback feedback;
        feedback.tm = tm;
        feedback.len = len;
        feedback.token = Hex2Str(ptr, len);
        feedbacks.push_back(feedback);
    }
}