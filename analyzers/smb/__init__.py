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
  'signing': {},
  'cifs_signing' : {},
  'smb2_signing' : {},
  'smb_dialects': [],
  'netbios': None, # check if NetBIOS is accessible
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

    for identifier, service in services.items():
      issues = service['issues']

      if service['smb_dialects']:
        self._analyze_dialects(service['smb_dialects'], self.recommendations, issues)
   
      if service['signing'] != None:
        self._analyze_signing(service['signing'], self.recommendations, issues)
         
      if service['netbios'] is True:
        issues.append(Issue("Netbios enabled"))
        
      if service['nbstat_info']:
        issues.append(Issue("Netbios Info",
                            info = service['nbstat_info']))
    
      if service['null_session'] is True:
        issues.append(Issue("Null session established"))

    return services

  def _analyze_signing(self, protocols, recommendations, issues):
    for protocol in protocols.keys():
      signing_enabled = True
      signing_required = True
          
      if protocols[protocol]['enabled'] != recommendations[protocol]['enabled']:
        signing_enabled = False
      
      if protocols[protocol]['required'] != recommendations[protocol]['required']:
        signing_required = False
        
      if "CIFS" in protocol:
        protocol = "CIFS/SMB1"
        
      if signing_enabled and not signing_required:
        issues.append(
          Issue(
            'Signing optional',
            proto = protocol
          )
        )
      
      if not signing_enabled and signing_required:
        issues.append(
          Issue(
            'Singning disabled but required',
            proto = protocol
          )
        )
        
      if not signing_enabled and not signing_required:
        issues.append(
          Issue(
            'Singing disabled',
            proto = protocol
          )
        )

  def _analyze_dialects(self, dialects, recommendations, issues):
        for dialect in dialects:
          if 'NT LM' in dialect:
            issues.append(
              Issue(
                "SMB dialect supported",
                version = dialect
              )
            )
            continue
          
          if dialect < recommendations['preferred_dialect']:
            issues.append(
              Issue(
                 "SMB dialect supported",
                 version = re.sub(r'(.)', r'\1.', dialect, 2)
              )
            )
