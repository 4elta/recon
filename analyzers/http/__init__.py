import copy
import csv
import datetime
import json
import pathlib
import re
import sys

SERVICE_SCHEMA = {
  'scheme': None,
  'host': None,
  'port': None,
  'response_headers': {},
  'response_body': None,
  'issues': [],
}

class Analyzer:

  def __init__(self, tool, recommendations):
    self.tool = tool
    self.recommendations = recommendations
    self.mandatory_directives = []

    self.services = []

    if self.tool == 'nmap':
      from .nmap import Parser
    else:
      sys.exit(f"unknown tool '{self.tool}'")

    self.parser = Parser()

  def analyze(self, files):
    # parse result files
    services = self.parser.parse_files(files[self.tool])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():

      issues = service['issues']

      if 'mandatory_headers' in self.recommendations:
        mandatory_headers = list(
          set(
            self.recommendations['mandatory_headers']
          ).difference(
            service['response_headers'].keys()
          )
        )

        # vor HTTP-only services remove the STS header from the list of mandatory headers
        if 'scheme' in service and service['scheme'] == 'http':
          try:
            mandatory_headers.remove('strict-transport-security')
          except:
            # we received an error while trying to remove an element from the list of missing headers
            # this means the STS header was NOT in the list.
            # this further means server sent the STS header.
            # https://datatracker.ietf.org/doc/html/rfc6797#section-7.2
            issues.append("`strict-transport-security` header: an HSTS host must not include this header in responses conveyed over non-secure transport (i.e. HTTP)")
            del service['response_headers']['strict-transport-security']


        for missing_header in mandatory_headers:
          issues.append(f"`{missing_header}` header missing")

      for header_name, header_values in service['response_headers'].items():
        if header_name in self.recommendations['header']:
          for header_value in header_values:
            self.run_check(
              [ 'header', header_name ],
              header_value,
              issues
            )

      '''
      special cases: vulnerability scanners

      for example, Nikto does not list the response headers; instead it lists various vulnerabilities it found.
      the parsers for scanners like that should collect those items in a dictionary (inside the "service" dictionary).
      "nikto" = {
        "issue001" = "issue description"
        "issue987" = "issue description"
        "issueFOO" = "bar"
      }

      the recommendations config file (for these tools) contains a list of IDs we are interested in.
      '''

      if tool in self.recommendations and tool in service:
        for issue_ID, issue in service[tool].items():
          if issue_ID in self.recommendations[tool]:
            issues.append(issue)

    return services

  def run_check(self, breadcrumbs, value, issues):
    names = []
    recommendation = self.recommendations

    for breadcrumb in breadcrumbs:
      recommendation = recommendation[breadcrumb]
      if 'name' in recommendation:
        names.append(recommendation['name'])

    match = True
    matches = {}

    if 'regex' in recommendation:
      p = re.compile(recommendation['regex'])
      m = p.search(value)

      match = match and bool(m)
      if m:
        matches = m.groupdict()

    if 'lower_bound' in recommendation:
      match = match and (int(value) >= recommendation['lower_bound'])

    if 'upper_bound' in recommendation:
      match = match and (int(value) <= recommendation['upper_bound'])

    if match and 'on_match' in recommendation:
      on_match = recommendation['on_match']
      self.handle_event(on_match, names, m, breadcrumbs, value, issues)

    if not match and 'on_mismatch' in recommendation:
      on_mismatch = recommendation['on_mismatch']
      self.handle_event(on_mismatch, names, None, breadcrumbs, value, issues)

  def handle_event(self, event_handler, names, match, breadcrumbs, value, issues):
    if 'issue' in event_handler:
      issues.append(f"{' '.join(names)} {event_handler['issue']}")
      return

    if 'next' in event_handler:
      for n in event_handler['next']:
        if match and n in match.groupdict():
          value = match.group(n)

        self.run_check(
          [*breadcrumbs, n],
          value,
          issues
        )

  def save_CSV(self, path, tool):
    delimiter = ','
    header = ['tool', 'asset', 'issues']

    with open(path, 'w') as f:
      csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(header)

      for identifier, service in self.services.items():
        for issue in service['issues']:
          row = [tool, identifier, issue]
          csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(row)
