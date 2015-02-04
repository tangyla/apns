#ifndef APNS_H
#define APNS_H

#include <stdint.h>
#include <string>
#include <vector>
#include <boost/noncopyable.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct ApnsFeedback {
    uint32_t tm;
    uint16_t len;
    std::string token;
};

void InitSSLLibrary(void);
void CloseSSLibrary(void);

class Apns : public boost::noncopyable {
public:
    Apns(const std::string& host,
         int port,
         const std::string& cert_pem,
         const std::string& key_pem,
         pem_password_cb *cb,
         void* cb_data);
    ~Apns(void);

    int PushMessage(const std::string& deviceToken,
                    const std::string& body,
                    const int badge = 9,
                    const std::string& sound = std::string("bingbong.aiff"));

    void FeedBack(std::vector<ApnsFeedback>& feedbacks);

private:
    void Conn(const std::string& host, int port);
    std::string Hex2Str(char* buf, size_t len);
    const char* Str2Hex(const char* str, char* buf, size_t szLen);
    std::string ConstructAps(const std::string& body, const int badge, const std::string& sound);

    SSL_CTX * ctx_;
    SSL* ssl_;
    int sock_;
};

#endif  // end APNS_H