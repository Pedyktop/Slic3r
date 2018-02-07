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
    typedef std::function<void(std::string, unsigned)> ErrorFn;

    struct Builder {
        std::unique_ptr<priv> p;

        Builder(const std::string &url);

        Builder& sizeLimit(size_t sizeLimit);
        Builder& setHeader(std::string name, const std::string &value);
        Builder& removeHeader(std::string name);
        Builder& header(const std::string &name, const std::string &value);
        Builder& formAdd(const std::string &name, const std::string &contents);
        Builder& formAddFile(const std::string &name, const std::string &filename);

        Builder& onComplete(CompleteFn fn);
        Builder& onError(ErrorFn fn);

        Ptr perform();
    };

    Http(Builder &&builder);

    static Builder get(std::string url);
    static Builder post(std::string url); // TODO
    ~Http();

    Http(const Http &) = delete;
    Http(Http &&) = delete;
    Http& operator=(const Http &) = delete;
    Http& operator=(Http &&) = delete;

    static void download();   // TODO: remove
private:
    std::unique_ptr<priv> p;

    void perform();
};


}

#endif
