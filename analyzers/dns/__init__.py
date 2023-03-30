import datetime
import importlib
import ipaddress
import json
import pathlib
import re
import sys

SERVICE_SCHEMA = {
  'address': None,
  'public': None,
  'port': None,
  'transport_protocol': None,
  'recursive': None, # whether or not this name server is a recursive DNS
  'DNSSEC': None, # whether or not this name server supports DNSSEC
  'ECS': None, # whether of not this name server supports EDNS Client Subnet (ECS)
  'info': {}, # misc information (rDNS, domain, `bind.version`, `id.server`, etc)
  'issues': [],
}

class Analyzer:

  def __init__(self, recommendations):
    self.recommendations = recommendations

    self.services = []

    self.set_tool('name_server')

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

      if service['public'] is None:
        if ipaddress.ip_address(service['address']).is_global:
          service['public'] = True

      if service['public']:
        if 'public' in self.recommendations and not self.recommendations['public']:
          issues.append("public DNS server")

        if service['recursive']:
          if service['transport_protocol'].upper() == 'UDP':
            issues.append("supports recursive DNS: this could be abused for traffic amplification attacks")
            # https://www.cloudflare.com/learning/dns/what-is-recursive-dns/

      if 'DNSSEC' in self.recommendations:
        if self.recommendations['DNSSEC'] and not service['DNSSEC']:
          issues.append("does not validate DNSSEC: this could lead to DNS cache poisoning")

      if service['recursive'] and 'ECS' in self.recommendations:
        if service['ECS'] and not self.recommendations['ECS']:
          issues.append("supports ECS: this might decrease users' privacy and could enable targeted DNS poisoning attacks")
          # https://yacin.nadji.us/docs/pubs/dimva16_ecs.pdf
        if not service['ECS'] and self.recommendations['ECS']:
          issues.append("does not support ECS: this might hinder load balancing")

      for key, value in service['info'].items():
        issues.append(f"additional information: `{key}={value}`")
        # version.bind: https://kb.isc.org/docs/aa-00359

    return services

