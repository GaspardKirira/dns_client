#include <dns_client/dns_client.hpp>
#include <iostream>

int main()
{
  dns_client::Options opt;
  opt.server_ip = "8.8.8.8";

  auto r = dns_client::resolve("example.com", opt);

  if (!r.error.empty())
  {
    std::cerr << "DNS error: " << r.error << "\n";
    return 1;
  }

  std::cout << "IPv4 addresses\n";
  for (const auto &ip : r.ipv4)
    std::cout << "  " << ip << "\n";

  std::cout << "IPv6 addresses\n";
  for (const auto &ip : r.ipv6)
    std::cout << "  " << ip << "\n";
}
