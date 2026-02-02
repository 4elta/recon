import datetime
import ipaddress
import json
import pathlib
import sys

from .. import Issue, AbstractAnalyzer

'''
TODO: remove this comment block.
the service dictionary provides a tool-agnostic view of a service's configuration.
additional information about the target (where the service is running),
obtained through the service, is less relevant for assessing the service's configuration/security.
'''
SERVICE_SCHEMA = {
  'host': None, # hostname or IP address
  'transport_protocol': None, # TCP or UDP
  'port': None, # port number

  # whether the service is publicly accessible (i.e. using a "global" IP address)
  'public': False,

  # all protocol versions the server speaks/supports
  'versions': set(),

  # TODO: add relevant info

  'issues': [],

  # information about the target, most probably gathered through that service
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

      # TODO: further analyze the parsed information (i.e. the `service` dictionary)

      # this is necessary in order to be able to export the service dictionary to JSON
      service['versions'] = list(service['versions'])

    return services
