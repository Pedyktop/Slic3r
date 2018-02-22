#include "Bonjour.hpp"

#include <cstdio>   // XXX
#include <cstdint>
#include <algorithm>
#include <unordered_map>
#include <array>
#include <vector>
#include <string>
#include <random>
#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/asio.hpp>

#include <iostream>   // XXX

using boost::optional;
using boost::system::error_code;
namespace endian = boost::endian;
namespace asio = boost::asio;
using boost::asio::ip::udp;


// TODO: Explain! Explain! Explain!
// TODO: Fuzzing test
// FIXME: integer warnings


namespace Slic3r {


static const unsigned char mdns_answer[] =
{
    /* 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0xb8, 0x27, 0xeb, 0x1a, 0x58, 0xf8, 0x00, 0x00, 0x08, 0x00,
    0x45, 0x00, 0x00, 0xd3, 0xf7, 0x26, 0x40, 0x00, 0xff, 0x11, 0xdf, 0x4d, 0x0a, 0x18, 0xc8, 0x3b,
    0x0a, 0x18, 0xc8, 0x39, 0x14, 0xe9, 0xb0, 0x39, 0x00, 0xbf, 0x27, 0xff, */ 0xee, 0x1b, 0x84, 0x00,
    0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x05, 0x5f, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5f,
    0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, 0xc0, 0x0c,
    0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x2c, 0x29, 0x4f, 0x63, 0x74, 0x6f, 0x50,
    0x72, 0x69, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x20, 0x22, 0x6f,
    0x63, 0x74, 0x6f, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x2d, 0x76, 0x6b, 0x2d, 0x74, 0x65, 0x73, 0x74,
    0x69, 0x6e, 0x67, 0x22, 0xc0, 0x0c, 0xc0, 0x2e, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x07, 0x06, 0x70, 0x61, 0x74, 0x68, 0x3d, 0x2f, 0xc0, 0x2e, 0x00, 0x21, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x0a, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x09, 0x6f, 0x63, 0x74, 0x6f,
    0x70, 0x69, 0x2d, 0x76, 0x6b, 0xc0, 0x17, 0xc0, 0x7f, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x19, 0xbd, 0xb6, 0xa5,
    0x75, 0xd9, 0xb6, 0xc0, 0x7f, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x0a,
    0x18, 0xc8, 0x3b,
};



struct DnsName: public std::string
{
    enum
    {
        MAX_RECURSION = 10,     // Keep this low
    };

    static optional<DnsName> decode(const std::vector<char> &buffer, ptrdiff_t &offset, unsigned depth = 0)
    {
        // We trust that the offset passed is bounds-checked properly,
        // including that there is at least one byte beyond that offset.
        // Any further arithmetic has to be bounds-checked here though.

        // Check for recursion depth to prevent parsing names that are nested too deeply
        // or end up cyclic:
        if (depth >= MAX_RECURSION) {
            return boost::none;
        }

        DnsName res;
        const auto size = buffer.size();

        while (true) {
            const char* ptr = buffer.data() + offset;
            char len = *ptr;
            if (len & 0xc0) {
                // This is a recursive label
                ptrdiff_t pointer = (len & 0x3f) << 8 | ptr[1];
                const auto nested = decode(buffer, pointer, depth + 1);
                if (!nested) {
                    return boost::none;
                } else {
                    if (res.size() > 0) {
                        res.push_back('.');
                    }
                    res.append(*nested);
                    offset += 2;
                    return std::move(res);
                }
            } else if (len == 0) {
                // This is a name terminator
                offset++;
                break;
            } else {
                // This is a regular label
                len &= 0x3f;
                if (len + offset + 1 >= size) {
                    return boost::none;
                }

                res.reserve(len);
                if (res.size() > 0) {
                    res.push_back('.');
                }

                ptr++;
                for (const auto end = ptr + len; ptr < end; ptr++) {
                    char c = *ptr;
                    if (c >= 0x20 && c <= 0x7f) {
                        res.push_back(c);
                    } else {
                        return boost::none;
                    }
                }

                offset += len + 1;
            }
        }

        if (res.size() > 0) {
            return std::move(res);
        } else {
            return boost::none;
        }
    }
};

struct DnsHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    enum
    {
        SIZE = 12,
    };

    static DnsHeader decode(const std::vector<char> &buffer) {
        DnsHeader res;
        const uint16_t *data_16 = reinterpret_cast<const uint16_t*>(buffer.data());
        res.id = endian::big_to_native(data_16[0]);
        res.flags = endian::big_to_native(data_16[1]);
        res.qdcount = endian::big_to_native(data_16[2]);
        res.ancount = endian::big_to_native(data_16[3]);
        res.nscount = endian::big_to_native(data_16[4]);
        res.arcount = endian::big_to_native(data_16[5]);
        return res;
    }
};

struct DnsQuestion
{
    enum
    {
        MIN_SIZE = 5,
    };

    DnsName name;
    uint16_t type;
    uint16_t qclass;

    DnsQuestion() :
        type(0),
        qclass(0)
    {}

    static optional<DnsQuestion> decode(const std::vector<char> &buffer, ptrdiff_t &offset)
    {
        auto qname = DnsName::decode(buffer, offset);
        if (!qname) {
            return boost::none;
        }

        DnsQuestion res;
        res.name = std::move(*qname);
        const uint16_t *data_16 = reinterpret_cast<const uint16_t*>(buffer.data() + offset);
        res.type = endian::big_to_native(data_16[0]);
        res.qclass = endian::big_to_native(data_16[1]);

        offset += 4;
        return std::move(res);
    }
};

struct DnsResource
{
    DnsName name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    std::vector<char> data;

    DnsResource() :
        type(0),
        rclass(0),
        ttl(0)
    {}

    static optional<DnsResource> decode(const std::vector<char> &buffer, ptrdiff_t &offset, ptrdiff_t &dataoffset)  // TODO: ref offset?
    {
        auto rname = DnsName::decode(buffer, offset);
        if (!rname) {
            return boost::none;
        }

        if (offset + 10 >= buffer.size()) {
            return boost::none;
        }

        DnsResource res;
        res.name = std::move(*rname);
        const uint16_t *data_16 = reinterpret_cast<const uint16_t*>(buffer.data() + offset);
        res.type = endian::big_to_native(data_16[0]);
        res.rclass = endian::big_to_native(data_16[1]);
        res.ttl = endian::big_to_native(*reinterpret_cast<const uint32_t*>(data_16 + 2));
        uint16_t rdlength = endian::big_to_native(data_16[4]);

        offset += 10;
        if (offset + rdlength > buffer.size()) {
            return boost::none;
        }

        dataoffset = offset;
        res.data = std::move(std::vector<char>(buffer.begin() + offset, buffer.begin() + offset + rdlength));
        offset += rdlength;

        return std::move(res);
    }
};

struct DnsRR_A
{
    enum { TAG = 0x1 };

    asio::ip::address_v4 ip;

    static void decode(optional<DnsRR_A> &result, const DnsResource &rr)
    {
        if (rr.data.size() == 4) {
            DnsRR_A res;
            const uint32_t ip = endian::big_to_native(*reinterpret_cast<const uint32_t*>(rr.data.data()));
            res.ip = asio::ip::address_v4(ip);
            result = std::move(res);
        }
    }
};

struct DnsRR_AAAA
{
    enum { TAG = 0x1c };

    asio::ip::address_v6 ip;

    static void decode(optional<DnsRR_AAAA> &result, const DnsResource &rr)
    {
        if (rr.data.size() == 16) {
            DnsRR_AAAA res;
            std::array<unsigned char, 16> ip;
            std::copy_n(rr.data.begin(), 16, ip.begin());
            res.ip = asio::ip::address_v6(ip);
            result = std::move(res);
        }
    }
};

struct DnsRR_SRV
{
    enum
    {
        TAG = 0x21,
        MIN_SIZE = 8,
    };

    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    DnsName hostname;

    static void decode(std::vector<DnsRR_SRV> &results, const std::vector<char> &buffer, const DnsResource &rr, ptrdiff_t dataoffset)
    {
        if (rr.data.size() < MIN_SIZE) {
            return;
        }

        DnsRR_SRV res;

        const uint16_t *data_16 = reinterpret_cast<const uint16_t*>(rr.data.data());
        res.priority = endian::big_to_native(data_16[0]);
        res.weight = endian::big_to_native(data_16[1]);
        res.port = endian::big_to_native(data_16[2]);

        ptrdiff_t offset = dataoffset + 6;
        auto hostname(std::move(DnsName::decode(buffer, offset)));   // FIXME: Ditto elsewhere

        if (hostname) {
            res.hostname = std::move(*hostname);
            results.emplace_back(std::move(res));
        }
    }
};

struct DnsMessage
{
    enum
    {
        MAX_SIZE = 4096,
        MAX_ANS = 30,
    };

    DnsHeader header;
    optional<DnsQuestion> question;
    std::vector<DnsResource> answers;

    optional<DnsRR_A> rr_a;
    optional<DnsRR_AAAA> rr_aaaa;
    std::vector<DnsRR_SRV> rr_srv;

    static optional<DnsMessage> decode(const std::vector<char> &buffer, optional<uint16_t> id_wanted = boost::none)
    {
        const auto size = buffer.size();
        if (size < DnsHeader::SIZE + DnsQuestion::MIN_SIZE || size > MAX_SIZE) {
            return boost::none;
        }

        DnsMessage res;
        res.header = DnsHeader::decode(buffer);

        if (id_wanted && *id_wanted != res.header.id) {
            return boost::none;
        }

        if (res.header.qdcount > 1 || res.header.ancount > MAX_ANS) {
            return boost::none;
        }

        ptrdiff_t offset = DnsHeader::SIZE;
        if (res.header.qdcount == 1) {
            res.question = DnsQuestion::decode(buffer, offset);
        }

        for (unsigned i = 0; i < res.header.ancount; i++) {
            ptrdiff_t dataoffset = 0;
            auto rr = DnsResource::decode(buffer, offset, dataoffset);
            if (!rr) {
                return boost::none;
            } else {
                res.parse_rr(buffer, *rr, dataoffset);
                res.answers.push_back(std::move(*rr));
            }
        }

        return std::move(res);
    }
private:
    void parse_rr(const std::vector<char> &buffer, const DnsResource &rr, ptrdiff_t dataoffset)
    {
        switch (rr.type) {
            case DnsRR_A::TAG: DnsRR_A::decode(this->rr_a, rr); break;
            case DnsRR_AAAA::TAG: DnsRR_AAAA::decode(this->rr_aaaa, rr); break;
            case DnsRR_SRV::TAG: DnsRR_SRV::decode(this->rr_srv, buffer, rr, dataoffset); break;
        }
    }
};


struct BonjourRequest
{
    static const asio::ip::address_v4 MCAST_IP4;
    static const uint16_t MCAST_PORT;

    static const char rq_template[];

    uint16_t id;
    std::vector<char> data;

    BonjourRequest();
};

const asio::ip::address_v4 BonjourRequest::MCAST_IP4{0xe00000fb};
const uint16_t BonjourRequest::MCAST_PORT = 5353;

const char BonjourRequest::rq_template[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x5f, 0x68, 0x74,
    0x74, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c,
    0x00, 0x01,
};

BonjourRequest::BonjourRequest() :
    id(0),
    data(rq_template, rq_template + sizeof(rq_template))
{
    std::random_device dev;
    std::uniform_int_distribution<uint16_t> dist;
    id = dist(dev);

    uint16_t id_big = endian::native_to_big(id);
    const char *id_char = reinterpret_cast<char*>(&id_big);
    data[0] = id_char[0];
    data[1] = id_char[1];
}



namespace Bonjour {
void pokus()
{
    BonjourRequest brq;
    printf("RQ ID: %hu = %hx -> [%hhx, %hhx]\n", brq.id, brq.id, brq.data[0], brq.data[1]);

    try {
        boost::asio::io_service io_service;
        udp::socket socket(io_service);
        socket.open(udp::v4());
        socket.set_option(udp::socket::reuse_address(true));
        udp::endpoint mcast(BonjourRequest::MCAST_IP4, BonjourRequest::MCAST_PORT);
        socket.send_to(asio::buffer(brq.data), mcast);

        std::vector<char> buffer(DnsMessage::MAX_SIZE);
        size_t reply_length = socket.receive(asio::buffer(buffer, buffer.size()));
        std::cerr << "Received reply: " << reply_length << std::endl;

        // TODO: Timed reading:
        // https://stackoverflow.com/questions/291871/how-to-set-a-timeout-on-blocking-sockets-in-boost-asio
        // http://www.ridgesolutions.ie/index.php/2012/12/13/boost-c-read-from-serial-port-with-timeout-example/
        // https://gist.github.com/snaewe/1192479
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}
}


}
