import ipaddress
import json
import sys

from .. import Issue, AbstractAnalyzer

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

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files)
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
          issues.append(Issue("public SSH server"))

      if service['protocol_version'] and service['protocol_version'] not in self.recommendations['protocol_versions']:
        issues.append(
          Issue(
            "protocol: supported",
            version = service['protocol_version']
          )
        )

      for protocol_version in self.recommendations['protocol_versions']:
        if not protocol_version == service['protocol_version']:
          issues.append(
            Issue(
              "protocol: not supported",
              version = protocol_version
            )
          )

      for deviation in list(set(service['key_exchange_methods']).difference(self.recommendations['key_exchange_methods'])):
        issues.append(
          Issue(
            "key exchange method",
            method = deviation
          )
        )

      for server_host_key in service['server_host_keys']:
        if server_host_key['type'] not in self.recommendations['server_host_keys'] or server_host_key['size'] < self.recommendations['server_host_keys'][server_host_key['type']]:
          issues.append(
            Issue(
              "server host key",
              key_type_size = f"`{server_host_key['type']}` {server_host_key['size']}"
            )
          )

      for deviation in list(set(service['encryption_algorithms']).difference(self.recommendations['encryption_algorithms'])):
        issues.append(
          Issue(
            "encryption algorithm",
            algorithm = deviation
          )
        )

      for deviation in list(set(service['MAC_algorithms']).difference(self.recommendations['MAC_algorithms'])):
        issues.append(
          Issue(
            "MAC algorithm",
            algorithm = deviation
          )
        )

      for deviation in list(set(service['client_authentication_methods']).difference(self.recommendations['client_authentication_methods'])):
        issues.append(
          Issue(
            "client authentication method",
            method = deviation
          )
        )

    return services
