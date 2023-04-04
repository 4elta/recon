import ipaddress
import json
import sys

from .. import AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'public': None,
  'port': None,
  'transport_protocol': None,
  'banner': None,
  'description': None,
  'protocol_version': None,
  'key_exchange_methods': [],
  'server_host_keys': {},
  'encryption_algorithms': [],
  'MAC_algorithms': [],
  'compression_algorithms': [],
  'client_authentication_methods': [],
  'issues': [],
}

SERVER_HOST_KEY_SCHEMA = {
  'type': None,
  'size': None
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
          issues.append("public SSH server")

      if service['protocol_version'] and service['protocol_version'] not in self.recommendations['protocol_versions']:
        issues.append(f"protocol supported: {service['protocol_version']}")

      for protocol_version in self.recommendations['protocol_versions']:
        if not protocol_version == service['protocol_version']:
          issues.append(f"protocol not supported: {protocol_version}")

      for deviation in list(set(service['key_exchange_methods']).difference(self.recommendations['key_exchange_methods'])):
        issues.append(f"key exchange method: `{deviation}`")

      for server_host_key in service['server_host_keys']:
        if server_host_key['type'] not in self.recommendations['server_host_keys'] or server_host_key['size'] < self.recommendations['server_host_keys'][server_host_key['type']]:
          issues.append(f"server host key: `{server_host_key['type']}` {server_host_key['size']} bits")

      for deviation in list(set(service['encryption_algorithms']).difference(self.recommendations['encryption_algorithms'])):
        issues.append(f"encryption algorithm: `{deviation}`")

      for deviation in list(set(service['MAC_algorithms']).difference(self.recommendations['MAC_algorithms'])):
        issues.append(f"MAC algorithm: `{deviation}`")

      for deviation in list(set(service['client_authentication_methods']).difference(self.recommendations['client_authentication_methods'])):
        issues.append(f"client authentication method: `{deviation}`")

    return services
