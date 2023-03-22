import datetime
import json
import packaging.version
import pathlib
import re
import sys

SERVICE_SCHEMA = {
  'address': None,
  'transport_protocol': None,
  'port': None,
  'version': None, # e.g. "4.2.8p15"
  'monlist': None,
  'info': {},
  'issues': [],
}

class Analyzer:

  def __init__(self, tool, recommendations):
    self.tool = tool
    self.recommendations = recommendations

    self.services = []

    if self.tool == 'nmap':
      from .nmap import Parser
    else:
      sys.exit(f"unknown tool '{self.tool}'")

    self.parser = Parser()

  def analyze(self, files):
    # parse result files
    services = self.parser.parse_files(files[self.tool])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

      if 'version' in self.recommendations:
        self.analyze_version(
          service['version'],
          self.recommendations['version'],
          issues
        )

      if service['monlist']:
        issues.append("vulnerable to traffic amplification (CVE-2013-5211)")
        # https://nvd.nist.gov/vuln/detail/CVE-2013-5211

      if len(service['info']):
        issues.append("vulnerable to information disclosure (CVE-2014-5209) and traffic amplification")

      for key, value in service['info'].items():
        issues.append(f'received data: `{key}="{value}"`')

    return services

  def analyze_version(self, version, recommendation, issues):
    if version == recommendation:
      return

    v = packaging.version.parse(version)
    r = packaging.version.parse(recommendation)

    if v < r:
      issues.append(f"outdated version: {version} < {recommendation}")
