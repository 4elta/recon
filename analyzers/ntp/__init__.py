import ipaddress
import json
import re

from .. import AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'public': None,
  'port': None,
  'version': None, # e.g. "4.2.8p15"
  'info': [],
  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def __init__(self, name, recommendations):
    super().__init__(name, recommendations)

    self.set_parser('ntp')

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
          issues.append("public NTP server")

      if 'version' in self.recommendations:
        self.analyze_version(
          service['version'],
          self.recommendations['version'],
          issues
        )

      '''
      for info in service['info']:
        issues.append(f"received data: `{info}`")
      '''
    return services

  def analyze_version(self, version, recommendation, issues):
    if version == recommendation:
      return

    if version is None:
      return

    issues.append(f"used version: `{version}` (recommended version: `{recommendation}`)")
