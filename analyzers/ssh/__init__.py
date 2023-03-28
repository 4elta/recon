import datetime
import importlib
import json
import pathlib
import sys

SERVICE_SCHEMA = {
  'address': None,
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

class Analyzer:

  def __init__(self, recommendations):
    self.recommendations = recommendations

    self.services = []

    self.set_tool('nmap')

  def set_tool(self, tool):
    module_path = pathlib.Path(
      pathlib.Path(__file__).resolve().parent,
      f'{tool}.py'
    )

    if not module_path.exists():
      sys.exit(f"unknown tool '{tool}'")

    self.tool = tool
    module = importlib.import_module(f'{__name__}.{tool}')
    self.parser = module.Parser()

  def analyze(self, files):
    # parse result files
    services = self.parser.parse_files(files[self.tool])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

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
