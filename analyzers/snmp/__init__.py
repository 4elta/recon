import datetime
import ipaddress
import re
import sys

from .. import Issue, AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'port': None,
  'transport_protocol': None,

  # whether the service is publicly accessible (i.e. using a "global" IP adress)
  'public': False,

  # list all the versions the server speaks (e.g. 'SNMPv2c')
  # https://www.rfc-editor.org/rfc/rfc3411#section-2.14
  'versions': set(),

  # security model:
  # SNMPv1
  # SNMPv2c
  # USM: https://www.rfc-editor.org/rfc/rfc3414
  # TSM: https://www.rfc-editor.org/rfc/rfc5591
  'security_model': None,

  # list all the strings that were accepted by the server:
  # 'public': '{type of access}'
  'community_strings': set(),

  'issues': [],

  # management information base.
  # https://www.rfc-editor.org/rfc/rfc3418
  # https://mibs.observium.org/all/
  'MIB': {},

  # miscellanous information
  'misc': {},
}

class Analyzer(AbstractAnalyzer):

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files)
    self.services = services

    self.__class__.logger.debug("parsing done")

    for identifier, service in services.items():
      self.__class__.logger.info(f"analyzing {identifier} ...")

      issues = service['issues']

      try:
        if ipaddress.ip_address(service['address']).is_global:
          service['public'] = True
      except ValueError:
        pass

      if service['public'] and 'public' in self.recommendations and not self.recommendations['public']:
        issues.append(Issue("public server"))

      if 'versions' in self.recommendations:
        for version in service['versions']:
          if version not in self.recommendations['versions']:
            issues.append(
              Issue(
                "version supported",
                version = version,
              )
            )

        for version in self.recommendations['versions']:
          if version not in service['versions']:
            issues.append(
              Issue(
                "version not supported",
                version = version,
              )
            )

      if 'community_strings' in self.recommendations and service['community_strings']:
        community_strings = set()
        for community_string in self.recommendations['community_strings']:
          if community_string.startswith('file://'):
            file_path = community_string[7:]
            with open(file_path) as f:
              lines = f.read().strip().split('\n')
              community_strings.update(lines)
          else:
            community_strings.add(community_string)

        for insecure_community_string in community_strings & service['community_strings']:
          issues.append(
            Issue(
              "insecure community string",
              community_string = insecure_community_string,
            )
          )

      for key, value in service['MIB'].items():
        if '_info' in value:
          info = value['_info']
          info_str = f"[{info['ID']}]({info['URL']})"
        else:
          info_str = f'`{key}` (MIB)'

        issues.append(
          Issue(
            "information disclosure",
            info = info_str,
          )
        )

      # this is necessary in order to be able to export the service dictionary to JSON
      service['versions'] = list(service['versions'])
      service['community_strings'] = list(service['community_strings'])

    return services

