#!/usr/bin/env python3

import argparse
import dns # https://github.com/rthalley/dnspython (sudo apt install python3-dnspython)
import dns.dnssec
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

  return str(response[0]).rstrip('.')

def is_recursive(domain, nameserver):
  # https://serverfault.com/a/1120946

  query = dns.message.make_query(
    domain,
    rdtype = dns.rdatatype.A,
    ednsflags = dns.flags.RA
  )

  if TRANSPORT_PROTOCOL == 'udp':
    response = dns.query.udp(query, nameserver, port=PORT)

  if TRANSPORT_PROTOCOL == 'tcp':
    response = dns.query.tcp(query, nameserver, port=PORT)

  return response.rcode() == 0

def supports_DNSSEC(domain, nameserver):
  # https://stackoverflow.com/a/26137120

  query = dns.message.make_query(
    domain,
    rdtype = dns.rdatatype.DNSKEY,
    want_dnssec = True
  )

  if TRANSPORT_PROTOCOL == 'udp':
    response = dns.query.udp(query, nameserver, port=PORT)

  if TRANSPORT_PROTOCOL == 'tcp':
    response = dns.query.tcp(query, nameserver, port=PORT)

  if response.rcode() != 0:
    return False

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
  address = args.address
  print(f"address: {address}")

  global PORT
  PORT = args.port
  print(f"port: {PORT}")

  global TRANSPORT_PROTOCOL
  TRANSPORT_PROTOCOL = args.transport_protocol
  print(f"transport protocol: {TRANSPORT_PROTOCOL}")

  result = {
    'address': address,
    'transport_protocol': TRANSPORT_PROTOCOL,
    'port': PORT,
    'public': False,
    'rDNS': None,
    'recursive': None,
    'DNSSEC': None,
  }

  result['public'] = ipaddress.ip_address(address).is_global
  print(f"public: {result['public']}")

  hostname = reverse_DNS_lookup(address)
  result['rDNS'] = hostname
  print(f"rDNS: {hostname}")

  result['recursive'] = is_recursive(hostname, address)
  print(f"recursive: {result['recursive']}")

  result['DNSSEC'] = supports_DNSSEC(hostname, address)
  print(f"DNSSEC: {result['DNSSEC']}")

  if args.json:
    with open(args.json, 'w') as f:
      json.dump(result, f, indent=2)

def main():
  parser = argparse.ArgumentParser()
  
  parser.add_argument('address')
  parser.add_argument('--transport_protocol', choices=['tcp', 'udp'], default=TRANSPORT_PROTOCOL)
  parser.add_argument('--port', type=int, default=PORT)
  parser.add_argument('--json', type=pathlib.Path)
  
  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
