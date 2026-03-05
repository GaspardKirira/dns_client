/**
 * @file dns_client.hpp
 * @brief Tiny DNS client (UDP) for A and AAAA lookups with optional async support.
 *
 * Features:
 * - Resolve A (IPv4) and AAAA (IPv6) records
 * - Custom DNS server (default 8.8.8.8:53)
 * - Timeout (ms)
 * - Deterministic parsing (no external deps)
 * - Async helper via std::async
 *
 * Notes:
 * - This is a minimal DNS-over-UDP implementation (RFC 1035 basics).
 * - TCP fallback is not implemented (large answers may be truncated).
 * - Internationalized domain names (IDN) are not converted (expects ASCII/punycode).
 *
 * Header-only. C++17+.
 */

#ifndef DNS_CLIENT_DNS_CLIENT_HPP
#define DNS_CLIENT_DNS_CLIENT_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <future>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace dns_client
{
  enum class QueryType : uint16_t
  {
    A = 1,
    AAAA = 28
  };

  struct Options
  {
    std::string server_ip = "8.8.8.8";
    uint16_t server_port = 53;
    int timeout_ms = 1500;
    bool recursion_desired = true;
  };

  struct Response
  {
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;

    // DNS header fields that can help debugging.
    uint16_t id = 0;
    uint8_t rcode = 0;      // 0 = NOERROR
    bool truncated = false; // TC bit

    std::string error; // non-empty if failed
  };

  /**
   * @brief Resolve A and AAAA records for a hostname (two queries).
   */
  inline Response resolve(std::string_view hostname, const Options &opt = Options{});

  /**
   * @brief Resolve only A records (IPv4).
   */
  inline Response resolve_a(std::string_view hostname, const Options &opt = Options{});

  /**
   * @brief Resolve only AAAA records (IPv6).
   */
  inline Response resolve_aaaa(std::string_view hostname, const Options &opt = Options{});

  /**
   * @brief Async variant (runs resolve() via std::async).
   */
  inline std::future<Response> resolve_async(std::string hostname, Options opt = Options{});

  namespace detail
  {
#if defined(_WIN32)
    struct WsaGuard
    {
      bool ok = false;

      WsaGuard()
      {
        WSADATA wsa{};
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
      }

      ~WsaGuard()
      {
        if (ok)
          WSACleanup();
      }
    };

    inline void closesocket_cross(int fd)
    {
      if (fd != INVALID_SOCKET)
        ::closesocket((SOCKET)fd);
    }
#else
    inline void closesocket_cross(int fd)
    {
      if (fd >= 0)
        ::close(fd);
    }
#endif

    inline uint16_t random_u16()
    {
      static thread_local std::mt19937 rng{std::random_device{}()};
      std::uniform_int_distribution<uint16_t> dist(0, 0xFFFF);
      return dist(rng);
    }

    inline void write_u16(std::vector<uint8_t> &buf, uint16_t v)
    {
      buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
      buf.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    inline void write_u32(std::vector<uint8_t> &buf, uint32_t v)
    {
      buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
      buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
      buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
      buf.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    inline uint16_t read_u16(const std::vector<uint8_t> &buf, size_t &off)
    {
      if (off + 2 > buf.size())
        throw std::runtime_error("dns_client: truncated u16");
      uint16_t v = (static_cast<uint16_t>(buf[off]) << 8) |
                   (static_cast<uint16_t>(buf[off + 1]));
      off += 2;
      return v;
    }

    inline uint32_t read_u32(const std::vector<uint8_t> &buf, size_t &off)
    {
      if (off + 4 > buf.size())
        throw std::runtime_error("dns_client: truncated u32");
      uint32_t v = (static_cast<uint32_t>(buf[off]) << 24) |
                   (static_cast<uint32_t>(buf[off + 1]) << 16) |
                   (static_cast<uint32_t>(buf[off + 2]) << 8) |
                   (static_cast<uint32_t>(buf[off + 3]));
      off += 4;
      return v;
    }

    inline void write_qname(std::vector<uint8_t> &buf, std::string_view hostname)
    {
      if (hostname.empty())
        throw std::runtime_error("dns_client: empty hostname");

      // Very small validation: forbid spaces and leading/trailing dot.
      if (hostname.front() == '.' || hostname.back() == '.')
        throw std::runtime_error("dns_client: invalid hostname (dot)");

      size_t label_start = 0;

      while (label_start < hostname.size())
      {
        size_t dot = hostname.find('.', label_start);
        size_t label_end = (dot == std::string_view::npos) ? hostname.size() : dot;
        size_t label_len = label_end - label_start;

        if (label_len == 0 || label_len > 63)
          throw std::runtime_error("dns_client: invalid label length");

        buf.push_back(static_cast<uint8_t>(label_len));

        for (size_t i = 0; i < label_len; ++i)
        {
          char c = hostname[label_start + i];
          if (c <= ' ' || c == '/')
            throw std::runtime_error("dns_client: invalid hostname character");
          buf.push_back(static_cast<uint8_t>(c));
        }

        if (dot == std::string_view::npos)
          break;
        label_start = dot + 1;
      }

      buf.push_back(0); // root terminator
    }

    inline void skip_name(const std::vector<uint8_t> &buf, size_t &off)
    {
      // DNS name can be labels or compression pointers.
      // Compression pointer: 11xxxxxx xxxxxxxx (0xC0..).
      // We just skip correctly without expanding.
      if (off >= buf.size())
        throw std::runtime_error("dns_client: name out of bounds");

      while (true)
      {
        if (off >= buf.size())
          throw std::runtime_error("dns_client: name truncated");
        uint8_t len = buf[off];

        if ((len & 0xC0) == 0xC0)
        {
          // pointer takes 2 bytes
          if (off + 2 > buf.size())
            throw std::runtime_error("dns_client: name pointer truncated");
          off += 2;
          return;
        }

        if (len == 0)
        {
          off += 1;
          return;
        }

        // label
        off += 1;
        if (off + len > buf.size())
          throw std::runtime_error("dns_client: label truncated");
        off += len;
      }
    }

    inline std::vector<uint8_t> build_query(std::string_view hostname, QueryType qtype, const Options &opt, uint16_t id)
    {
      std::vector<uint8_t> q;
      q.reserve(512);

      // Header (12 bytes)
      // ID
      write_u16(q, id);

      // Flags
      // QR=0, OPCODE=0, AA=0, TC=0, RD=opt, RA=0, Z=0, RCODE=0
      uint16_t flags = 0;
      if (opt.recursion_desired)
        flags |= 0x0100; // RD
      write_u16(q, flags);

      // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
      write_u16(q, 1);
      write_u16(q, 0);
      write_u16(q, 0);
      write_u16(q, 0);

      // Question
      write_qname(q, hostname);
      write_u16(q, static_cast<uint16_t>(qtype)); // QTYPE
      write_u16(q, 1);                            // QCLASS = IN

      return q;
    }

    inline int create_udp_socket()
    {
#if defined(_WIN32)
      SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (s == INVALID_SOCKET)
        return -1;
      return (int)s;
#else
      int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      return s;
#endif
    }

    inline bool set_recv_timeout(int sock, int timeout_ms)
    {
#if defined(_WIN32)
      DWORD tv = (timeout_ms < 0) ? 0 : (DWORD)timeout_ms;
      return ::setsockopt((SOCKET)sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) == 0;
#else
      timeval tv{};
      tv.tv_sec = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;
      return ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) == 0;
#endif
    }

    inline bool send_udp(int sock, const sockaddr_in &dst, const std::vector<uint8_t> &packet)
    {
#if defined(_WIN32)
      int n = ::sendto((SOCKET)sock, (const char *)packet.data(), (int)packet.size(), 0,
                       (const sockaddr *)&dst, (int)sizeof(dst));
      return n == (int)packet.size();
#else
      ssize_t n = ::sendto(sock, packet.data(), packet.size(), 0,
                           (const sockaddr *)&dst, sizeof(dst));
      return n == (ssize_t)packet.size();
#endif
    }

    inline bool recv_udp(int sock, std::vector<uint8_t> &out, int max_bytes)
    {
      out.assign((size_t)max_bytes, 0);

#if defined(_WIN32)
      int n = ::recvfrom((SOCKET)sock, (char *)out.data(), (int)out.size(), 0, nullptr, nullptr);
      if (n <= 0)
        return false;
      out.resize((size_t)n);
      return true;
#else
      ssize_t n = ::recvfrom(sock, out.data(), out.size(), 0, nullptr, nullptr);
      if (n <= 0)
        return false;
      out.resize((size_t)n);
      return true;
#endif
    }

    inline void parse_answers(Response &resp, const std::vector<uint8_t> &buf, QueryType qtype)
    {
      size_t off = 0;

      resp.id = read_u16(buf, off);
      uint16_t flags = read_u16(buf, off);

      const bool qr = (flags & 0x8000) != 0;
      const bool tc = (flags & 0x0200) != 0;
      const uint8_t rcode = static_cast<uint8_t>(flags & 0x000F);

      resp.truncated = tc;
      resp.rcode = rcode;

      if (!qr)
        throw std::runtime_error("dns_client: not a response");

      uint16_t qd = read_u16(buf, off);
      uint16_t an = read_u16(buf, off);
      uint16_t ns = read_u16(buf, off);
      uint16_t ar = read_u16(buf, off);

      // Skip questions
      for (uint16_t i = 0; i < qd; ++i)
      {
        skip_name(buf, off);
        (void)read_u16(buf, off); // QTYPE
        (void)read_u16(buf, off); // QCLASS
      }

      // Parse answers
      for (uint16_t i = 0; i < an; ++i)
      {
        skip_name(buf, off);
        uint16_t type = read_u16(buf, off);
        uint16_t klass = read_u16(buf, off);
        (void)read_u32(buf, off); // TTL
        uint16_t rdlen = read_u16(buf, off);

        if (off + rdlen > buf.size())
          throw std::runtime_error("dns_client: rdata truncated");

        if (klass == 1 && type == static_cast<uint16_t>(QueryType::A) && rdlen == 4)
        {
          char ip_str[INET_ADDRSTRLEN]{};
          ::inet_ntop(AF_INET, (const void *)&buf[off], ip_str, sizeof(ip_str));
          resp.ipv4.emplace_back(ip_str);
        }
        else if (klass == 1 && type == static_cast<uint16_t>(QueryType::AAAA) && rdlen == 16)
        {
          char ip_str[INET6_ADDRSTRLEN]{};
          ::inet_ntop(AF_INET6, (const void *)&buf[off], ip_str, sizeof(ip_str));
          resp.ipv6.emplace_back(ip_str);
        }

        off += rdlen;
      }

      // We ignore NS and AR sections for now.
      (void)ns;
      (void)ar;

      // If the server returned an error, expose it.
      if (resp.rcode != 0)
      {
        resp.error = "dns_client: server returned rcode=" + std::to_string((int)resp.rcode);
      }

      // If truncated, inform caller (still can have partial data).
      if (resp.truncated && resp.error.empty())
      {
        resp.error = "dns_client: truncated response (TCP fallback not implemented)";
      }

      // If the caller asked A or AAAA and got nothing, keep as success but empty.
      (void)qtype;
    }

    inline Response query_once(std::string_view hostname, QueryType qtype, const Options &opt)
    {
      Response resp{};

#if defined(_WIN32)
      WsaGuard wsa;
      if (!wsa.ok)
      {
        resp.error = "dns_client: WSAStartup failed";
        return resp;
      }
#endif

      int sock = create_udp_socket();
      if (sock < 0)
      {
        resp.error = "dns_client: failed to create UDP socket";
        return resp;
      }

      // Ensure socket gets closed.
      struct SockGuard
      {
        int fd;
        ~SockGuard() { detail::closesocket_cross(fd); }
      } guard{sock};

      (void)set_recv_timeout(sock, opt.timeout_ms);

      sockaddr_in dst{};
      dst.sin_family = AF_INET;
      dst.sin_port = htons(opt.server_port);

      if (::inet_pton(AF_INET, opt.server_ip.c_str(), &dst.sin_addr) != 1)
      {
        resp.error = "dns_client: invalid server_ip (IPv4 only in this minimal client)";
        return resp;
      }

      uint16_t id = random_u16();
      auto packet = build_query(hostname, qtype, opt, id);

      if (!send_udp(sock, dst, packet))
      {
        resp.error = "dns_client: sendto failed";
        return resp;
      }

      std::vector<uint8_t> raw;
      if (!recv_udp(sock, raw, 2048))
      {
        resp.error = "dns_client: recvfrom timeout or failed";
        return resp;
      }

      try
      {
        parse_answers(resp, raw, qtype);
        // Safety: ensure response id matches our query id.
        if (resp.id != id)
        {
          resp.error = "dns_client: response id mismatch";
        }
      }
      catch (const std::exception &e)
      {
        resp.error = std::string("dns_client: parse error: ") + e.what();
      }

      return resp;
    }

    inline void merge(Response &dst, const Response &src)
    {
      if (!src.error.empty() && dst.error.empty())
        dst.error = src.error;
      dst.id = src.id;
      dst.rcode = src.rcode;
      dst.truncated = src.truncated;

      dst.ipv4.insert(dst.ipv4.end(), src.ipv4.begin(), src.ipv4.end());
      dst.ipv6.insert(dst.ipv6.end(), src.ipv6.begin(), src.ipv6.end());
    }

  } // namespace detail

  inline Response resolve_a(std::string_view hostname, const Options &opt)
  {
    return detail::query_once(hostname, QueryType::A, opt);
  }

  inline Response resolve_aaaa(std::string_view hostname, const Options &opt)
  {
    // This client uses an IPv4 DNS server address (sockaddr_in).
    // AAAA is still fine: query type is AAAA, transport remains IPv4 to the DNS server.
    return detail::query_once(hostname, QueryType::AAAA, opt);
  }

  inline Response resolve(std::string_view hostname, const Options &opt)
  {
    Response out{};

    auto r4 = resolve_a(hostname, opt);
    detail::merge(out, r4);

    auto r6 = resolve_aaaa(hostname, opt);
    detail::merge(out, r6);

    return out;
  }

  inline std::future<Response> resolve_async(std::string hostname, Options opt)
  {
    return std::async(std::launch::async, [h = std::move(hostname), opt]()
                      { return resolve(h, opt); });
  }

} // namespace dns_client

#endif // DNS_CLIENT_DNS_CLIENT_HPP
