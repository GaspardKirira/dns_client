#include <dns_client/dns_client.hpp>
#include <iostream>

int main()
{
  auto fut = dns_client::resolve_async("example.com");

  auto r = fut.get();

  if (!r.error.empty())
  {
    std::cerr << "DNS error: " << r.error << "\n";
    return 1;
  }

  for (const auto &ip : r.ipv4)
    std::cout << "IPv4: " << ip << "\n";

  for (const auto &ip : r.ipv6)
    std::cout << "IPv6: " << ip << "\n";
}
