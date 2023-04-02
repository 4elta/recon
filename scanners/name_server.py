#!/usr/bin/env python3

# scans a name server (DNS) and lists its configuration

import argparse
import dns # https://github.com/rthalley/dnspython (sudo apt install python3-dnspython)
import dns.resolver
import dns.zone
import ipaddress
import json
import pathlib
import re
import sys

# domain which should not fall under the authority of the name server to be tested
TEST_DOMAIN = "example.com"

# domain which will result in a `SERVFAIL` status when the name server validates DNSSEC
# https://support.quad9.net/hc/en-us/articles/360050642431-What-does-a-block-from-Quad9-look-like-
# https://developers.cloudflare.com/support/dns/dnssec/troubleshooting-dnssec/#troubleshooting-dnssec-validation-with-dig
TEST_DOMAIN_VALIDATE_DNSSEC = "brokendnssec.net"

ECS_ADDRESS = "0.0.0.0"
ECS_PREFIX = 24

PORT = 53
TRANSPORT_PROTOCOL = 'udp'

def reverse_DNS_lookup(address):
  try:
    response = dns.resolver.resolve(
      dns.reversename.from_address(address),
      rdtype = dns.rdatatype.PTR
    )
  except:
    return

  return str(response[0])

def send_query(query, nameserver):
  try:
    if TRANSPORT_PROTOCOL == 'udp':
      return dns.query.udp(query, nameserver, port=PORT)

    if TRANSPORT_PROTOCOL == 'tcp':
      return dns.query.tcp(query, nameserver, port=PORT)
  except:
    return

def get_SOA(domain, nameserver):
  if domain is None:
    return

  query = dns.message.make_query(
    domain,
    rdtype = dns.rdatatype.SOA
  )

  response = send_query(query, nameserver)

  if response is None or response.rcode() != dns.rcode.NOERROR:
    return

  if len(response.authority):
    return str(response.authority[0].name)

  if len(response.answer):
    return str(response.answer[0].name)

  return domain

def test_recursive(domain, nameserver):
  # https://serverfault.com/a/1120946

  query = dns.message.make_query(
    domain,
    rdtype = dns.rdatatype.A,
    ednsflags = dns.flags.RA
  )

  response = send_query(query, nameserver)

  if response is None:
    return

  return response.rcode() == dns.rcode.NOERROR

def test_DNSSEC_validation(invalid_domain, nameserver):
  query = dns.message.make_query(
    invalid_domain,
    rdtype = dns.rdatatype.A,
    want_dnssec = True
  )

  response = send_query(query, nameserver)

  if response is None:
    return

  return response.rcode() == dns.rcode.SERVFAIL

def test_ECS_support(domain, nameserver):
  query = dns.message.make_query(
    domain,
    rdtype = dns.rdatatype.A,
    use_edns = 0,
    options = [ dns.edns.ECSOption(ECS_ADDRESS, ECS_PREFIX) ]
  )

  response = send_query(query, nameserver)

  if response is None:
    return

  for option in response.options:
    if 'ECS' in option.to_text():
      return True

  return False

def get_CH_TXT(name, nameserver, NSID=False):
  info = {}

  query = dns.message.make_query(
    name,
    rdtype = dns.rdatatype.TXT,
    rdclass = dns.rdataclass.CH
  )

  if NSID:
    # https://www.ietf.org/rfc/rfc5001.html#section-2.1
    query.use_edns(
      edns = 0,
      options = [ dns.edns.GenericOption(dns.edns.OptionType.NSID, b"") ],
    )
    query.flags |= dns.flags.AD # add the 'additional' flag

  response = send_query(query, nameserver)

  if response is None or response.rcode() != dns.rcode.NOERROR:
    return info

  for opt in response.options:
    if opt.otype == dns.edns.NSID:
      nsid = opt.data.decode()
      info['NSID'] = nsid
      print(f"NSID: {nsid}")
      break

  if len(response.answer) == 0:
    return info

  answer = response.answer[0]
  for item in answer:
    if item.rdtype == dns.rdatatype.TXT and item.rdclass == dns.rdataclass.CH:
      info_bytes = b''.join(item.strings)
      info_string = info_bytes.decode()
      info[name] = info_string
      print(f"{name}: {info_string}")

  return info

def get_additional_info(address):
  info = {}

  hostname = reverse_DNS_lookup(address)
  if hostname:
    info['rDNS'] = hostname
    print(f"rDNS: {hostname}")

  domain = get_SOA(hostname, address)
  if domain:
    info['domain'] = domain
    print(f"domain: {domain}")

  info.update(get_CH_TXT('bind.version', address))

  info.update(get_CH_TXT('id.server', address, True))

  return info

def test_AXFR(domain, nameserver):
  # https://github.com/rthalley/dnspython/blob/master/examples/xfr.py
  try:
    xfr = dns.query.xfr(
      nameserver,
      domain
    )

    zone = dns.zone.from_xfr(xfr)

    print("AXFR:")
    zone_info = []
    for key in sorted(zone.nodes.keys()):
      for info in zone[key].to_text(key).splitlines():
        zone_info.append(info)
        print(f"  {info}")

    return zone_info
  except:
    return

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
  print(f"transport protocol: {TRANSPORT_PROTOCOL.upper()}")

  is_recursive = test_recursive(TEST_DOMAIN, address)
  print(f"recursive: {is_recursive}")

  validates_DNSSEC = test_DNSSEC_validation(TEST_DOMAIN_VALIDATE_DNSSEC, address)
  print(f"DNSSEC: {validates_DNSSEC}")

  supports_ECS = test_ECS_support(TEST_DOMAIN, address)
  print(f"ECS: {supports_ECS}")

  info = get_additional_info(address)

  domain = None

  if args.domain:
    domain = args.domain
  elif 'domain' in info:
    domain = info['domain']

  permits_AXFR = None
  if domain:
    permits_AXFR = test_AXFR(domain, address)

  if args.json:
    result = {
      'address': address,
      'public': public,
      'transport_protocol': TRANSPORT_PROTOCOL.upper(),
      'port': PORT,
      'recursive': is_recursive,
      'DNSSEC': validates_DNSSEC,
      'ECS': supports_ECS,
      'AXFR': permits_AXFR,
      'info': info,
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
    '--domain',
    help = "the domain for which the name server has authority; if not specified, it will be determined via rDNS and SOA"
  )

  parser.add_argument(
    '--json',
    help = "in addition to the scan result being printed to STDOUT, also save the analysis as a JSON document",
    type = pathlib.Path
  )
  
  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
