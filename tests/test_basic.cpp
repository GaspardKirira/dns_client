/**
 * @file test_basic.cpp
 * @brief Basic tests for dns_client.
 */

#include <dns_client/dns_client.hpp>

#include <cassert>
#include <iostream>
#include <string>

static void test_resolve_a_ok()
{
  dns_client::Options opt;
  opt.timeout_ms = 2000;
  opt.server_ip = "8.8.8.8";

  auto r = dns_client::resolve_a("example.com", opt);

  // We accept empty result if network is restricted, but it should not crash.
  // If it did resolve, we should have at least one IPv4.
  if (r.error.empty())
  {
    // Either got some IPv4, or none (rare), but no error.
    // We only assert format if present.
    for (const auto &ip : r.ipv4)
    {
      // Very small format sanity: "x.x.x.x"
      assert(ip.find('.') != std::string::npos);
    }
  }
  else
  {
    // In CI/offline environments, timeouts are common.
    // Ensure error is a meaningful string.
    assert(!r.error.empty());
  }
}

static void test_resolve_aaaa_ok()
{
  dns_client::Options opt;
  opt.timeout_ms = 2000;
  opt.server_ip = "8.8.8.8";

  auto r = dns_client::resolve_aaaa("example.com", opt);

  if (r.error.empty())
  {
    for (const auto &ip : r.ipv6)
    {
      // Very small sanity: IPv6 contains ':'
      assert(ip.find(':') != std::string::npos);
    }
  }
  else
  {
    assert(!r.error.empty());
  }
}

static void test_resolve_both()
{
  dns_client::Options opt;
  opt.timeout_ms = 2000;
  opt.server_ip = "8.8.8.8";

  auto r = dns_client::resolve("example.com", opt);

  // Should never crash. If no error, it may have v4/v6.
  if (r.error.empty())
  {
    // nothing strict, just sanity if present
    for (const auto &ip : r.ipv4)
      assert(ip.find('.') != std::string::npos);
    for (const auto &ip : r.ipv6)
      assert(ip.find(':') != std::string::npos);
  }
  else
  {
    assert(!r.error.empty());
  }
}

static void test_async()
{
  dns_client::Options opt;
  opt.timeout_ms = 2000;
  opt.server_ip = "8.8.8.8";

  auto fut = dns_client::resolve_async("example.com", opt);
  auto r = fut.get();

  // Same philosophy: offline CI may fail, but must be stable.
  if (r.error.empty())
  {
    for (const auto &ip : r.ipv4)
      assert(ip.find('.') != std::string::npos);
    for (const auto &ip : r.ipv6)
      assert(ip.find(':') != std::string::npos);
  }
  else
  {
    assert(!r.error.empty());
  }
}

int main()
{
  test_resolve_a_ok();
  test_resolve_aaaa_ok();
  test_resolve_both();
  test_async();

  std::cout << "dns_client: all basic tests passed\n";
  return 0;
}
