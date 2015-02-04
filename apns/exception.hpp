#ifndef APNS_EXCEPTION_HPP
#define APNS_EXCEPTION_HPP

#include <exception>
#include <string>

class Exception : public std::exception {
public:
    explicit Exception(std::string& msg)
        :msg_(msg)
    {}

    explicit Exception(const char* msg)
        :msg_(msg)
    {}

    virtual ~Exception(void) throw ()
    {}

    const char * what(void) const throw () {
        return msg_.c_str();
    }

private:
    const std::string msg_;

};

#endif