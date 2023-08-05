import datetime
import importlib
import ipaddress
import json
import pathlib
import re
import sys

from .. import Issue, AbstractAnalyzer

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
          issues.append(Issue("public DNS server"))

        if service['recursive']:
          if service['transport_protocol'].upper() == 'UDP':
            issues.append(Issue("recursive DNS"))
            issues.append("supports recursive DNS: this could be abused for traffic amplification attacks")

      if 'DNSSEC' in self.recommendations and service['DNSSEC'] is not None:
        if self.recommendations['DNSSEC'] and not service['DNSSEC']:
          issues.append(Issue("DNSSEC not validated"))

      if service['recursive'] and 'ECS' in self.recommendations:
        if service['ECS'] and not self.recommendations['ECS']:
          issues.append(Issue("ECS: supported"))
        if not service['ECS'] and self.recommendations['ECS']:
          issues.append(Issue("ECS: not supported"))

      if service['AXFR']:
        issues.append(Issue("AXFR"))

      for key, value in service['info'].items():
        issues.append(
          Issue(
            "additional info",
            info = f"`{key}={value}`"
          )
        )

    return services

