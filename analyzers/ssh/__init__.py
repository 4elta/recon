import ipaddress
import json
import re
import sys

from .. import Issue, AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'public': None,
  'port': None,
  'transport_protocol': None,
  'banner': None,
  'description': None,
  'versions': [], # ['1.0', '2.0']
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

      if 'versions' in self.recommendations:
        for version in service['versions']:
          if version not in self.recommendations['versions']:
            issues.append(
              Issue(
                "protocol: supported",
                version = service['version']
              )
            )

        for version in self.recommendations['versions']:
          if version not in service['versions']:
            issues.append(
              Issue(
                "protocol: not supported",
                version = version
              )
            )

      self._analyze(
        "key exchange method",
        service['key_exchange_methods'],
        self.recommendations['key_exchange_methods'],
        issues
      )

      self._analyze(
        "encryption algorithm",
        service['encryption_algorithms'],
        self.recommendations['encryption_algorithms'],
        issues
      )

      self._analyze(
        "MAC algorithm",
        service['MAC_algorithms'],
        self.recommendations['MAC_algorithms'],
        issues
      )

      self._analyze(
        "client authentication method",
        service['client_authentication_methods'],
        self.recommendations['client_authentication_methods'],
        issues
      )

      self._analyze_server_host_keys(
        service['server_host_keys'],
        self.recommendations['server_host_keys'],
        issues
      )

    return services

  def _analyze(self, parameter_type, parameters, recommendations, issues):
    for parameter in parameters:
      match_found = False
      for pattern in recommendations:
        if re.match(pattern, parameter):
          match_found = True
          break

      if not match_found:
        issues.append(
          Issue(
            parameter_type,
            method = parameter, algorithm = parameter # some parameters are "methods", some are "algorithms"
          )
        )

  def _analyze_server_host_keys(self, keys, recommendations, issues):
    for key in keys:
      key_type = key['type']
      key_size = key['size']
      type_match = False
      size_OK = False
      for pattern, min_size in recommendations.items():
        if re.match(pattern, key_type):
          type_match = True
          if key_size > min_size:
            size_OK = True
          break

      if not type_match or not size_OK:
        issues.append(
          Issue(
            "server host key",
            key_type_size = f"`{key_type}` {key_size}"
          )
        )
