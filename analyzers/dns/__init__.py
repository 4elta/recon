import datetime
import importlib
import ipaddress
import json
import pathlib
import re
import sys

from .. import AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'public': None,
  'port': None,
  'transport_protocol': None,
  'recursive': None, # whether or not this name server is a recursive DNS
  'DNSSEC': None, # whether or not this name server validates DNSSEC
  'ECS': None, # whether or not this name server supports EDNS Client Subnet (ECS)
  'AXFR': None, # whether or not this name server permits AXFR; if it does, this key will hold the DNS zone
  'info': {}, # misc information (rDNS, domain, `bind.version`, `id.server`, etc)
  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def __init__(self, name, recommendations):
    super().__init__(name, recommendations)

    self.set_parser('nase')

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files[self.parser_name])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

      if service['public'] is None:
        if ipaddress.ip_address(service['address']).is_global:
          service['public'] = True

      if service['public']:
        if 'public' in self.recommendations and not self.recommendations['public']:
          issues.append("public DNS server")

        if service['recursive']:
          if service['transport_protocol'].upper() == 'UDP':
            issues.append("supports recursive DNS: this could be abused for traffic amplification attacks")
            # https://www.cloudflare.com/learning/dns/what-is-recursive-dns/

      if 'DNSSEC' in self.recommendations and service['DNSSEC'] is not None:
        if self.recommendations['DNSSEC'] and not service['DNSSEC']:
          issues.append("does not validate DNSSEC: this could lead to DNS cache poisoning")

      if service['recursive'] and 'ECS' in self.recommendations:
        if service['ECS'] and not self.recommendations['ECS']:
          issues.append("supports ECS: this might decrease users' privacy and could enable targeted DNS poisoning attacks")
          # https://yacin.nadji.us/docs/pubs/dimva16_ecs.pdf
        if not service['ECS'] and self.recommendations['ECS']:
          issues.append("does not support ECS: this might hinder load balancing")

      if service['AXFR']:
        issues.append("permits AXFR: this might expose potentially sensitive information")

      for key, value in service['info'].items():
        issues.append(f"additional information: `{key}={value}`")
        # version.bind: https://kb.isc.org/docs/aa-00359

    return services

