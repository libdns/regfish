regfish for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/regfish)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [regfish DNS API](https://regfish.readme.io/), allowing you to manage DNS records.

## Compatibility

This provider is compatible with libdns v1.1.0 and supports the following record types:
- **A/AAAA records** - IPv4 and IPv6 addresses (using `libdns.Address`)
- **MX records** - Mail exchange records with preference values (using `libdns.MX`)
- **TXT records** - Text records (using `libdns.TXT`)
- **CNAME records** - Canonical name records (using `libdns.CNAME`)
- **NS records** - Name server records (using `libdns.NS`)
- **SRV records** - Service records with priority, weight, and port (using `libdns.SRV`)
- **CAA records** - Certificate Authority Authorization records (using `libdns.CAA`)
- **Other record types** - Fallback to generic RR format (using `libdns.RR`)

## Configuration

The provider expects the following configuration:

- APIToken - a regfish API key (from Account, Security, API keys)

## Features

- Automatic parsing of MX record preference values from parsed records
- Support for SRV record priority values
- Proper handling of IPv4 and IPv6 addresses
- Thread-safe operations with mutex protection
- Comprehensive error handling and validation

## Notes

This project was authored to support the needs for [Caddy Server](https://caddyserver.com)
