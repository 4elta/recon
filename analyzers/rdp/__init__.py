import datetime
import importlib
import ipaddress
import json
import pathlib
import re
import sys

SERVICE_SCHEMA = {
  'address': None,
  'port': None,
  'transport_protocol': None,

  'version': None, # e.g. "5.x"

  'protocol': None,
  # standard RDP security
  # 0x00: PROTOCOL_RDP i.e. "standard RDP security"

  # enhanced RDP security
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/422e59a0-98c8-4a28-af9f-235a572b6e4d
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817
  # 0x01: PROTOCOL_SSL e.g. "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"
  # 0x02: PROTOCOL_HYBRID i.e. "CredSSP"
  # 0x04: PROTOCOL_RDSTLS i.e. "RDSTLS"
  # 0x08: PROTOCOL_HYBRID_EX i.e. "CredSSP with Early User Authorization"
  # 0x10: PROTOCOL_RDSAAD i.e. "RDS AAD"

  'encryption': None,
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

      #TODO: implement this

    return services

