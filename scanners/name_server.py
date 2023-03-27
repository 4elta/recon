#!/usr/bin/env python3

# scans a name server (DNS) and lists its configuration

import argparse
import dns # https://github.com/rthalley/dnspython (sudo apt install python3-dnspython)
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.resolver
import dns.reversename
import ipaddress
import json
import pathlib
import sys

PORT = 53
TRANSPORT_PROTOCOL = 'udp'

def reverse_DNS_lookup(address):
  response = dns.resolver.resolve(
    dns.reversename.from_address(address),
    rdtype = dns.rdatatype.PTR
  )

  return str(response[0])

def send_query(query, nameserver):
  if TRANSPORT_PROTOCOL == 'udp':
    return dns.query.udp(query, nameserver, port=PORT)

  if TRANSPORT_PROTOCOL == 'tcp':
    return dns.query.tcp(query, nameserver, port=PORT)

def get_SOA(domain, nameserver):
  query = dns.message.make_query(
    domain,
    rdtype = dns.rdatatype.SOA
  )

  response = send_query(query, nameserver)

  if response.rcode() != dns.rcode.NOERROR:
    return

  if len(response.authority):
    return str(response.authority[0].name)

  if len(response.answer):
    return str(response.answer[0].name)

  return domain

def is_recursive(domain, nameserver):
  # https://serverfault.com/a/1120946

  query = dns.message.make_query(
    domain,
    rdtype = dns.rdatatype.A,
    ednsflags = dns.flags.RA
  )

  response = send_query(query, nameserver)

  return response.rcode() == dns.rcode.NOERROR

def supports_DNSSEC(domain, nameserver):
  # https://stackoverflow.com/a/26137120

  query = dns.message.make_query(
    domain,
    rdtype = dns.rdatatype.DNSKEY,
    want_dnssec = True
  )

  response = send_query(query, nameserver)

  if response.rcode() != dns.rcode.NOERROR:
    return False

  '''
  Messages carried by UDP are restricted to 512 bytes (not counting the IP
  or UDP headers).  Longer messages are truncated and the TC bit is set in
  the header.
  -- https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.1
  '''
  if response.flags & dns.flags.TC != 0:
    # TODO: currently, we assume that the truncated data contains valid keys, hence we return "True"
    return True

  answer = response.answer

  if len(answer) != 2:
    return False

  try:
    dns.dnssec.validate(
      answer[0],
      answer[1],
      { dns.name.from_text(domain) : answer[0] }
    )
  except dns.dnssec.ValidationFailure:
    return False

  return True

def process(args):
  try:
    address = ipaddress.ip_address(args.address)
    print(f"address: {address}")

    public = address.is_global
    print(f"public: {public}")
  except ValueError as e:
    sys.exit('\n'.join(e.args))

  # from here on the IP address must be a string instead of an instance of IPv(4|6)Address
  address = str(address)

  global PORT
  PORT = args.port
  print(f"port: {PORT}")

  global TRANSPORT_PROTOCOL
  TRANSPORT_PROTOCOL = args.transport_protocol
  print(f"transport protocol: {TRANSPORT_PROTOCOL}")

  hostname = reverse_DNS_lookup(address)
  print(f"rDNS: {hostname}")

  domain = get_SOA(hostname, address)
  print(f"domain: {domain}")

  recursive = is_recursive("example.com", address)
  print(f"recursive: {recursive}")

  DNSSEC = supports_DNSSEC(domain, address)
  print(f"DNSSEC: {DNSSEC}")

  if args.json:
    result = {
      'address': address,
      'public': public,
      'transport_protocol': TRANSPORT_PROTOCOL,
      'port': PORT,
      'rDNS': hostname,
      'domain': domain,
      'recursive': recursive,
      'DNSSEC': DNSSEC,
    }

    with open(args.json, 'w') as f:
      json.dump(result, f, indent=2)

def main():
  parser = argparse.ArgumentParser()
  
  parser.add_argument(
    'address',
    help = "the IP address of the name server to be scanned"
  )

  parser.add_argument(
    '--transport_protocol',
    help = f"the transport protocol (i.e. UDP/TCP) which the name server is using (default: '{TRANSPORT_PROTOCOL}')",
    choices = [ 'tcp', 'udp' ],
    default = TRANSPORT_PROTOCOL
  )

  parser.add_argument(
    '--port',
    help = f"the port number where the name server is listening for DNS queries (default: {PORT})",
    type = int,
    default = PORT
  )

  parser.add_argument(
    '--json',
    help = "in addition to the scan result being printed to STDOUT, also save the analysis as a JSON document",
    type = pathlib.Path
  )
  
  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
