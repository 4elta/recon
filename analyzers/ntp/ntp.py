import copy
import json

from .. import Issue, AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the `ntp` scanner.

  $ ntp --json "{result_file}.json" {address} 2>&1 | tee "{result_file}.log"
  '''

  def __init__(self):
    super().__init__()

    self.name = 'ntp'
    self.file_type = 'json'

  def parse_file(self, path):
    super().parse_file(path)

    with open(path) as f:
      result = json.load(f)

    identifier = f"{result['address']}:{result['port']} ({self.transport_protocol})"
    if identifier in self.services:
      return

    service = copy.deepcopy(SERVICE_SCHEMA)
    service.update(result)

    if 'mode_6' in service and service['mode_6']:
      service['issues'].append(
        Issue(
          "Mode 6",
          **service['mode_6']
        )
      )

    if 'mode_7' in service and service['mode_7']:
      service['issues'].append(
        Issue(
          "Mode 7",
          **service['mode_7']
        )
      )

    self.services[identifier] = service
