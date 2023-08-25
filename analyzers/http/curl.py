import copy
import re

from .. import AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the curl index scan.

  $ curl --silent --verbose --insecure --show-error --max-time 10 {scheme}://{hostname}:{port}/ 2>&1 | tee --append "{result_file}.log"
  '''

  def __init__(self):
    super().__init__()

    self.name = 'curl'
    self.file_type = 'log'

  def parse_file(self, path):
    super().parse_file(path)

    pattern_info = re.compile(r'^\*\s+(?P<info>.+)')
    pattern_request = re.compile(r'^> (?P<request>.+)')
    pattern_response = re.compile(r'^< (?P<response>.+)')
    pattern_body = re.compile(r'^(?P<body>(?![*>}<{][\s]).*)')

    pattern_info_host = re.compile(r'Connected to (?P<host>[^\s]+) \((?P<address>[^)]+)\) port (?P<port>\d+)')
    pattern_info_https = re.compile(r'SSL connection using .+')

    scheme = 'http'
    host = None
    port = None
    requests = []
    responses = []
    body = []

    with open(path) as f:
      file_content = f.read()

    for line in file_content.split('\n'):
      match = pattern_info.match(line)
      if match:
        info = match.group('info').strip()

        if not info:
          continue

        if host is None:
          match = pattern_info_host.match(info)
          if match:
            host = match.group('host')
            port = match.group('port')
            continue

        match = pattern_info_https.match(info)
        if match:
          scheme = 'https'
          continue

      match = pattern_request.match(line)
      if match:
        request = match.group('request')
        requests.append(request)
        continue

      match = pattern_response.match(line)
      if match:
        response = match.group('response')
        responses.append(response)
        continue

      match = pattern_body.match(line)
      if match:
        body.append(match.group('body'))

    if host is None or port is None:
      # could not parse host and/or port
      return

    identifier = f"{scheme}://{host}:{port}"

    service = copy.deepcopy(SERVICE_SCHEMA)
    self.services[identifier] = service

    service['scheme'] = scheme
    service['host'] = host
    service['port'] = port

    service['response_headers'] = self._parse_http_headers(responses)
    service['response_body'] = '\n'.join(body)

  def _parse_http_headers(self, responses):
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
    p = re.compile(r'\s*(?P<name>[A-Za-z-]+):\s*(?P<value>.+)\s*')

    response_headers = {}

    for response in responses:
      match = p.match(response)

      if not match:
        continue

      header_name = match.group('name').lower()
      header_value = match.group('value')

      if header_name not in response_headers:
        response_headers[header_name] = []

      response_headers[header_name].append(header_value)

    return response_headers
