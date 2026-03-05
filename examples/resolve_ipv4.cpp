#include <dns_client/dns_client.hpp>
#include <iostream>

int main()
{
  auto r = dns_client::resolve_a("example.com");

  if (!r.error.empty())
  {
    std::cerr << "DNS error: " << r.error << "\n";
    return 1;
  }

  for (const auto &ip : r.ipv4)
    std::cout << ip << "\n";
}
