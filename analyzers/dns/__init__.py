import datetime
import ipaddress
import json
import packaging.version
import pathlib
import re
import sys

SERVICE_SCHEMA = {
  'address': None,
  'public': None,
  'transport_protocol': None,
  'port': None,
  'rDNS': None,
  'recursive': None,
  'DNSSEC': None,
  'issues': [],
}

class Analyzer:

  def __init__(self, tool, recommendations):
    self.tool = tool
    self.recommendations = recommendations

    self.services = []

    if self.tool == 'dns_tester':
      from .dns_tester import Parser
      self.parser = Parser()

    if self.tool == 'nmap':
      from .nmap import Parser
      self.parser = Parser()

    if not self.parser:
      sys.exit(f"unknown tool '{self.tool}'")

  def analyze(self, files):
    # parse result files
    services = self.parser.parse_files(files[self.tool])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

      if service['public'] is None:
        if ipaddress.ip_address(service['address']).is_global:
          service['public'] = True

      if service['public']:
        issues.append("public DNS server")

        if service['recursive']:
          issues.append("recursive DNS queries could be abused for traffic amplification attacks")
          # https://www.cloudflare.com/learning/dns/what-is-recursive-dns/

        if service['DNSSEC'] is False:
          issues.append("vulnerable to DNS cache poisoning attacks")

    return services
