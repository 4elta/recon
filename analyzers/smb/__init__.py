import re
import sys

from .. import Issue, AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'dialects': {}, # for each protocol (CIFS, SMB2) hold a list of supported dialects
  'signing': {}, # for each protocol (CIFS, SMB2) hold information about 'enabled' and 'required'
  'access': [], # anonymous, password, Kerberos, NTLM hash, non-existing user
  'issues': [],
  'misc': [], # misc information (NetBIOS, etc); shown with the host, after all issues
  'info': [], # additional (debug) information; shown at the end of the analysis
}

class Analyzer(AbstractAnalyzer):

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files)
    self.services = services

    for identifier, service in services.items():
      issues = service['issues']

      if service['dialects']:
        self._analyze_dialects(service['dialects'], self.recommendations, issues)
   
      if service['signing']:
        self._analyze_signing(service['signing'], self.recommendations, issues)

      if service['access']:
        self._analyze_access(service['access'], self.recommendations, issues)

      for info in service['misc']:
        issues.append(
          Issue(
            "additional info",
            info = info
          )
        )

    return services

  def _analyze_signing(self, signing, recommendations, issues):
    for protocol, signing_info in signing.items():
      protocol_nice = protocol
      if protocol == "CIFS":
        protocol_nice = "SMB1/CIFS"

      if (
        protocol not in recommendations['signing']
        or signing_info['required'] != recommendations['signing'][protocol]['required']
      ):
        issues.append(
          Issue(
            f"signing r:{signing_info['required']}",
            protocol = protocol_nice
          )
        )

  def _analyze_dialects(self, dialects, recommendations, issues):
    for protocol, dialect_list in dialects.items():
      protocol_nice = protocol
      if protocol == "CIFS":
        protocol_nice = "SMB1/CIFS"

      if protocol not in recommendations['dialect']:
        issues.append(Issue("protocol supported", protocol = protocol_nice))

      for dialect in dialect_list:
        if protocol not in recommendations['dialect'] or dialect < recommendations['dialect'][protocol]:
          issues.append(
            Issue(
              "dialect supported",
              protocol = protocol_nice,
              dialect = dialect
            )
          )

  def _analyze_access(self, access, recommendations, issues):
    for a in access:
      if a not in recommendations['authentications']:
        if a in ['anonymous', 'non-existing user']:
          issues.append(Issue(f'improper access control: {a}'))
        else:
          issues.append(
            Issue(
              'improper access control',
              authentication = a
            )
          )

