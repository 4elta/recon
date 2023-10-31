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
  'SMBv1': None,
  'SMBv2': None,
  'port': None,
  'preferred_dialect': '3.0',
  'SMBv1_only': None,
  'signing': None, # whether signing is enabled and/or required
  'netbios': None # wether SMB over NetBIOS is accessible
  'os_build': None, # OS Build id
  'os_release': None, # OS Release version
  'null_session': None, # whether or not a null session could be established
  'info': {}, # misc information (rDNS, domain, `bind.version`, `id.server`, etc)
  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def __init__(self, name, recommendations):
    super().__init__(name, recommendations)

    self.set_parser('enum4linux-ng')

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files[self.parser_name])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

      if service['SMBv1'] is True:
          issues.append(Issue("SMBv1 is supported"))

      if service['SMBv2'] is True:
          issues.append(Issue("SMBv2 is supported"))

      if service['signing'] is False:
          issues.append(Issue("Signing is not required"))

      if service['null_session'] is True:
          issues.append(Issue("Null session established"))

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

