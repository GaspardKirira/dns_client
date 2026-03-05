# dns_client

Minimal DNS resolver for IPv4 and IPv6 lookups.

`dns_client` provides a small deterministic DNS client for resolving domain names
using standard UDP DNS queries.

Header-only. No external dependencies.

## Download

https://vixcpp.com/registry/pkg/gaspardkirira/dns_client

## Why dns_client?

Domain name resolution is a fundamental part of modern backend systems.

Applications frequently need to resolve hostnames to IP addresses for:

- HTTP clients
- service discovery
- monitoring systems
- microservice communication
- network diagnostics
- infrastructure tooling
- distributed systems

Most C++ projects rely on large networking frameworks or platform-specific APIs.

`dns_client` provides a minimal alternative.

It implements basic DNS queries using UDP with a small deterministic codebase.

No external DNS libraries.
No framework dependencies.

Just simple DNS resolution.

## Features

- Resolve IPv4 addresses (A records)
- Resolve IPv6 addresses (AAAA records)
- Combined resolution (IPv4 + IPv6)
- Configurable DNS server
- Timeout configuration
- Async resolution helper
- Deterministic parsing
- Header-only simplicity

No external dependencies.

No runtime allocations beyond standard containers.

## Installation

### Using Vix Registry

```bash
vix add gaspardkirira/dns_client
vix deps
```

### Manual

```bash
git clone https://github.com/GaspardKirira/dns_client.git
```

Add the `include/` directory to your project.

## Dependency

Requires C++17 or newer.

Uses only the standard library and system socket APIs.

## Quick examples

### Resolve hostname

```cpp
#include <dns_client/dns_client.hpp>
#include <iostream>

int main()
{
    auto r = dns_client::resolve("example.com");

    if (!r.error.empty())
    {
        std::cerr << r.error << std::endl;
        return 1;
    }

    for (const auto& ip : r.ipv4)
        std::cout << ip << std::endl;
}
```

### Resolve IPv4 only

```cpp
#include <dns_client/dns_client.hpp>
#include <iostream>

int main()
{
    auto r = dns_client::resolve_a("example.com");

    for (const auto& ip : r.ipv4)
        std::cout << ip << std::endl;
}
```

### Async resolution

```cpp
#include <dns_client/dns_client.hpp>
#include <iostream>

int main()
{
    auto future = dns_client::resolve_async("example.com");

    auto result = future.get();

    for (const auto& ip : result.ipv4)
        std::cout << ip << std::endl;
}
```

## API overview

Core functions:

- `dns_client::resolve(hostname)`
- `dns_client::resolve_a(hostname)`
- `dns_client::resolve_aaaa(hostname)`
- `dns_client::resolve_async(hostname)`

Configuration:

- `dns_client::Options`

Response structure:

- `dns_client::Response`

## DNS behavior

Queries are performed using UDP.

Supported record types:

| Record | Description |
|--------|-------------|
| A      | IPv4 address |
| AAAA   | IPv6 address |

Default DNS server:

- `8.8.8.8:53`

The resolver can be configured via `dns_client::Options`.

## Limitations

This implementation focuses on simplicity.

Not implemented:

- TCP fallback for large responses
- DNSSEC validation
- EDNS extensions
- CNAME chain resolution
- DNS caching

These features can be implemented on top of this layer if needed.

## Complexity

| Operation             | Time complexity |
|----------------------|-----------------|
| DNS query             | O(n) |
| DNS response parsing  | O(n) |

Where `n` is the DNS packet size.

Typical packets are under 512 bytes.

## Design principles

- Deterministic behavior
- Minimal implementation
- No framework dependencies
- Header-only simplicity
- Predictable network behavior

This library focuses strictly on DNS resolution.

If you need:

- DNS caching
- service discovery
- load balancing
- distributed name systems
- advanced DNS features

Build them on top of this layer.

## Tests

Run:

```bash
vix build
vix test
```

Tests verify:

- A record resolution
- AAAA record resolution
- async queries
- error handling
- timeout behavior

## License

MIT License\
Copyright (c) Gaspard Kirira

