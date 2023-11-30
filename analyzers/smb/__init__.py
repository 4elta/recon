import datetime
import importlib
import ipaddress
import json
import pathlib
import re
import sys

from .. import Issue, AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'preferred_dialect': '3.1.1',
  'SMBv1_only': None,
  'smb_dialects': [],
  'smbv1_signing' : None,
  'smb_signing': None, # whether signing is enabled and/or required
  'netbios': None, # wether SMB over NetBIOS is accessible
  'os_build': None, # OS Build id
  'nbstat_info': None,
  'os_release': None, # OS Release version
  'null_session': None, # whether or not a null session could be established
  'info': {}, # misc information (rDNS, domain, `bind.version`, `id.server`, etc)
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

#      if service['SMBv1'] is True:
#          issues.append(Issue("SMBv1 is supported"))

#      if service['SMBv2'] is True:
#          issues.append(Issue("SMBv2 is supported"))
      if service['smb_dialects']:
        for dialect in service['smb_dialects']:
          issues.append(Issue("SMB dialect supported",
                              version = dialect))
          
      if service['smbv1_signing'] is True:
        issues.append(Issue("SMBv1 signing disabled"))            

      if service['smb_signing']:
        issues.append(Issue("SMB signing incorrect",
                            issue = service['smb_signing']))

      if service['netbios'] is True:
        issues.append(Issue("Netbios enabled"))
        
      if service['nbstat_info']:
        issues.append(Issue("Netbios Info",
                            info = service['nbstat_info']))
    
      if service['null_session'] is True:
        issues.append(Issue("Null session established"))

    return services

