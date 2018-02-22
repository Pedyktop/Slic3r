#include "Http.hpp"

#include <cstdlib>
#include <functional>
#include <thread>
#include <iostream>
#include <tuple>
#include <boost/format.hpp>

#include <curl/curl.h>

#include "OctoPrint.hpp"
#include "Bonjour.hpp"   // XXX


// XXX: style


namespace Slic3r {


// Private

class CurlGlobalInit
{
    static const CurlGlobalInit instance;

    CurlGlobalInit()  { ::curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlGlobalInit() { ::curl_global_cleanup(); }
};

struct Http::priv
{
    enum {
        DEFAULT_SIZE_LIMIT = 5 * 1024 * 1024,
    };

    ::CURL *curl;
    ::curl_httppost *form;
    ::curl_httppost *form_end;
    ::curl_slist *headerlist;
    std::string buffer;
    size_t limit;

    std::thread io_thread;
    Http::CompleteFn completefn;
    Http::ErrorFn errorfn;

    priv(const std::string &url);
    ~priv();

    static size_t writecb(void *data, size_t size, size_t nmemb, void *userp);
    std::string body_size_error();
    void http_perform();
};

Http::priv::priv(const std::string &url) :
    curl(::curl_easy_init()),
    form(nullptr),
    form_end(nullptr),
    headerlist(nullptr)
{
    if (curl == nullptr) {
        throw std::runtime_error(std::string("Could not construct Curl object"));
    }

    ::curl_easy_setopt(curl, CURLOPT_URL, url.c_str());   // curl makes a copy internally
    // TODO: Get slicer version in here:
    ::curl_easy_setopt(curl, CURLOPT_USERAGENT, "Slic3r Prusa Edition/1.0");
}

Http::priv::~priv()
{
    ::curl_easy_cleanup(curl);
    ::curl_formfree(form);
    ::curl_slist_free_all(headerlist);
}

size_t Http::priv::writecb(void *data, size_t size, size_t nmemb, void *userp)
{
    auto self = static_cast<priv*>(userp);
    const char *cdata = static_cast<char*>(data);
    const size_t realsize = size * nmemb;

    const size_t limit = self->limit > 0 ? self->limit : DEFAULT_SIZE_LIMIT;
    if (self->buffer.size() + realsize > limit) {
        // This makes curl_easy_perform return CURLE_WRITE_ERROR
        return 0;
    }

    self->buffer.append(cdata, realsize);

    return realsize;
}

std::string Http::priv::body_size_error()
{
    return (boost::format("HTTP body data size exceeded limit (%1% bytes)") % limit).str();
}

void Http::priv::http_perform()
{
    ::curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    ::curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    ::curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecb);
    ::curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<void*>(this));

#ifndef NDEBUG
    ::curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif

    if (headerlist != nullptr) {
        ::curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    }

    if (form != nullptr) {
        ::curl_easy_setopt(curl, CURLOPT_HTTPPOST, form);
    }

    CURLcode res = ::curl_easy_perform(curl);
    long http_status = 0;
    ::curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

    if (res != CURLE_OK) {
        std::string error;
        if (res == CURLE_WRITE_ERROR) {
            error = std::move(body_size_error());
        } else {
            error = ::curl_easy_strerror(res);
        };

        if (errorfn) {
            errorfn(std::move(buffer), std::move(error), http_status);
        }
    } else {
        if (completefn) {
            completefn(std::move(buffer), http_status);
        }
    }
}

Http::Http(const std::string &url) : p(new priv(url)) {}


// Public

Http::Http(Http &&other) : p(std::move(other.p)) {}

Http::~Http()
{
    if (p && p->io_thread.joinable()) {
        p->io_thread.detach();
    }
}


Http& Http::size_limit(size_t sizeLimit)
{
    if (p) { p->limit = sizeLimit; }
    return *this;
}

Http& Http::header(std::string name, const std::string &value)
{
    if (!p) { return * this; }

    if (name.size() > 0) {
        name.append(": ").append(value);
    } else {
        name.push_back(':');
    }
    p->headerlist = curl_slist_append(p->headerlist, name.c_str());
    return *this;
}

Http& Http::remove_header(std::string name)
{
    if (p) {
        name.push_back(':');
        p->headerlist = curl_slist_append(p->headerlist, name.c_str());
    }

    return *this;
}

Http& Http::ca_file(const std::string &name)
{
    if (p) {
        ::curl_easy_setopt(p->curl, CURLOPT_CAINFO, name.c_str());
    }

    return *this;
}

Http& Http::form_add(const std::string &name, const std::string &contents)
{
    if (p) {
        ::curl_formadd(&p->form, &p->form_end,
            CURLFORM_COPYNAME, name.c_str(),
            CURLFORM_COPYCONTENTS, contents.c_str(),
            CURLFORM_END
        );
    }

    return *this;
}

Http& Http::form_add_file(const std::string &name, const std::string &filename)
{
    if (p) {
        ::curl_formadd(&p->form, &p->form_end,
            CURLFORM_COPYNAME, name.c_str(),
            CURLFORM_FILE, filename.c_str(),
            CURLFORM_CONTENTTYPE, "application/octet-stream",
            CURLFORM_END
        );
    }

    return *this;
}

Http& Http::on_complete(CompleteFn fn)
{
    if (p) { p->completefn = std::move(fn); }
    return *this;
}

Http& Http::on_error(ErrorFn fn)
{
    if (p) { p->errorfn = std::move(fn); }
    return *this;
}

Http::Ptr Http::perform()
{
    auto self = std::make_shared<Http>(std::move(*this));

    if (self->p) {
        auto io_thread = std::thread([self](){
                self->p->http_perform();
            });
        self->p->io_thread = std::move(io_thread);
    }

    return self;
}

void Http::perform_sync()
{
    if (p) { p->http_perform(); }
}

void Http::pokus()     // TODO: remove
{
    Bonjour::pokus();

    // static const std::string url{"https://raw.githubusercontent.com/prusa3d/Slic3r-settings/master/Slic3r%20settings%20MK2S%20MK2MM%20and%20MK3/slic3r.ini"};

    // static const std::string url{"https://httpbin.org/status/500"};
    // static const std::string url{"https://httpbin.org/status/418"};
    // static const std::string url{"https://httpbin.org/redirect/6"};
    // static const std::string url{"http://httpbin.org/post"};

    // static const std::string url{"http://10.0.0.46/api/files"};
    // static const std::string url{"http://10.0.0.46/api/files/local"};

    // auto http = Http::get(url)
    // auto http = Http::post(url)
    //     .setHeader("X-Api-Key", "70E4CFD0E0D7423CB6B1CF055DBAEFA5")
    //     .formAdd("print", "true")
    //     .formAddFile("file", "/home/vojta/prog/tisk/jesterka/jesterka.gcode")
    //     .onComplete([](std::string body, unsigned status) {
    //         std::cerr << "Request complete! Status: " << status << std::endl
    //             << "\n" << body << std::endl;
    //     })
    //     .onError([](std::string body, unsigned status) {
    //         std::cerr << "Request error: `" << body << "`, status: "
    //             << status << std::endl;
    //     })
    //     .perform();

    // send_gcode("10.0.0.46", "70E4CFD0E0D7423CB6B1CF055DBAEFA5", "/home/vojta/prog/tisk/jesterka/jesterka.gcode");
}

Http Http::get(std::string url)
{
    return std::move(Http{std::move(url)});
}

Http Http::post(std::string url)
{
    Http http{std::move(url)};
    curl_easy_setopt(http.p->curl, CURLOPT_POST, 1L);
    return http;
}


}
