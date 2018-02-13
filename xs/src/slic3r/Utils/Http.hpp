#ifndef slic3r_Http_hpp_
#define slic3r_Http_hpp_

#include <memory>
#include <string>
#include <functional>

#include <boost/system/error_code.hpp>
#include <boost/beast/http/verb.hpp>


namespace Slic3r {

// TODO: neni v typemap.xspt ... vadi to?

/// Represetns a Http request
class Http : public std::enable_shared_from_this<Http> {
private:
    struct priv;
public:
    typedef std::shared_ptr<Http> Ptr;
    typedef std::function<void(std::string, unsigned)> CompleteFn;
    typedef std::function<void(std::string, std::string, unsigned)> ErrorFn;

    Http(Http &&other);

    static Http get(std::string url);
    static Http post(std::string url);
    ~Http();

    Http(const Http &) = delete;
    Http& operator=(const Http &) = delete;
    Http& operator=(Http &&) = delete;

    Http& size_limit(size_t sizeLimit);
    Http& header(std::string name, const std::string &value);
    Http& remove_header(std::string name);
    Http& ca_file(const std::string &filename);
    Http& form_add(const std::string &name, const std::string &contents);
    Http& form_add_file(const std::string &name, const std::string &filename);

    Http& on_complete(CompleteFn fn);
    Http& on_error(ErrorFn fn);

    Ptr perform();
    void perform_sync();

    static void download();   // TODO: remove
private:
    Http(const std::string &url);

    std::unique_ptr<priv> p;
};


}

#endif