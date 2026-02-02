import copy
import json

from ... import Issue, AbstractParser
from .. import SERVICE_SCHEMA

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

    if 'tests' in service:
      for ntp_version, test in service['tests'].items():
        if '6' in test and test['6']:
          for opcode, result in test['6'].items():
            amplification_factor = result['amplification_factor']
            service['issues'].append(
              Issue(
                "mode 6 + amplification",
                version = ntp_version,
                opcode = opcode,
                amplification_factor = amplification_factor,
              )
            )

            for data in result['data']:
              service['misc'].append(data)

        if '7' in test and test['7']:
          for implementation, request_codes in test['7'].items():
            for req_code, result in request_codes.items():
              amplification_factor = result['amplification_factor']
              service['issues'].append(
                Issue(
                  "mode 7 + amplification",
                  version = ntp_version,
                  implementation = implementation,
                  req_code = req_code,
                  amplification_factor = amplification_factor,
                )
              )

              for data in result['data']:
                service['misc'].append(data)

    self.services[identifier] = service
