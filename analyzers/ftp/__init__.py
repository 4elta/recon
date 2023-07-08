import ipaddress
import json
import re

from .. import AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'port': None,
  'transport_protocol': None,

  'public': None,

  # FTP Secure aka FTP over TLS
  'FTPS': None,

  'anonymous': None,

  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def __init__(self, name, recommendations):
    super().__init__(name, recommendations)

    self.set_parser('nmap')

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files[self.parser_name])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

      try:
        if ipaddress.ip_address(service['address']).is_global:
          service['public'] = True
      except ValueError:
        pass

      if service['public']:
        if 'public' in self.recommendations and not self.recommendations['public']:
          issues.append("public FTP server")

      if 'FTPS' in self.recommendations:
        if self.recommendations['FTPS'] and not service['FTPS']:
          issues.append("does not support FTPS")

      if 'anonymous' in self.recommendations:
        if service['anonymous'] == True and not self.recommendations['anonymous']:
          issues.append("allows anonymous access")

    return services

