import ipaddress
import json
import re

from .. import AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'port': None,
  'transport_protocol': None,

  'public': None,

  'protocols': [],
  # standard RDP security
  # 0x00: PROTOCOL_RDP i.e. "standard RDP security"

  # enhanced RDP security
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/422e59a0-98c8-4a28-af9f-235a572b6e4d
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817
  # 0x01: PROTOCOL_SSL e.g. "SSL 3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"
  # 0x02: PROTOCOL_HYBRID i.e. "CredSSP"
  # 0x04: PROTOCOL_RDSTLS i.e. "RDSTLS"
  # 0x08: PROTOCOL_HYBRID_EX i.e. "CredSSP with Early User Authorization"
  # 0x10: PROTOCOL_RDSAAD i.e. "RDS AAD Auth"

  'encryption_level': 'ENCRYPTION_LEVEL_LOW',
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f1c7c93b-94cc-4551-bb90-532a0185246a
  # 0x0: ENCRYPTION_LEVEL_NONE i.e. when "enhanced RDP security" is used
  # 0x1: ENCRYPTION_LEVEL_LOW
  # 0x2: ENCRYPTION_LEVEL_CLIENT
  # 0x3: ENCRYPTION_LEVEL_HIGH
  # 0x4: ENCRYPTION_LEVEL_FIPS

  'NLA': None,
  # Network Level Authentication

  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def __init__(self, name, recommendations):
    super().__init__(name, recommendations)

    self.set_parser('nmap')

  def analyze(self, files, lang):
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
          issues.append(_("public RDP server"))

      if 'protocols' in self.recommendations:
        self._analyze_protocols(
          service['protocols'],
          self.recommendations['protocols'],
          issues
        )

      if 'encryption_level' in self.recommendations:
        if service['encryption_level'] != self.recommendations['encryption_level']:
          message = _("supported encryption level")
          issues.append(f"{message}: `{service['encryption_level']}`")

      if 'NLA' in self.recommendations:
        if not service['NLA'] and self.recommendations['NLA']:
          issues.append(_("does not support NLA: this could enable denial-of-service attacks on the server"))

    return services

  def _analyze_protocols(self, protocols, recommendation, issues):
    for deviation in list(set(protocols).difference(recommendation)):
      message = _("protocol supported")
      issues.append(f"{message}: `{deviation}`")

    '''
    for deviation in list(set(recommendation).difference(protocol_versions)):
      issues.append(f"protocol not supported: `{deviation}`")
    '''
