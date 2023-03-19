import json
import re

from .. import AbstractAnalyzer

SERVICE_SCHEMA = {
  'scheme': None,
  'host': None,
  'port': None,
  'response_headers': {},
  'response_body': None,
  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def __init__(self, name, recommendations):
    super().__init__(name, recommendations)

    self.services = []

    match tool:
        case 'nmap':  
            from .nmap import Parser
        case 'nikto':
            from .nikto import Parser
        case _:
            sys.exit(f"unknown tool '{self.tool}'")

    self.parser = Parser()

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files[self.parser_name])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():

      issues = service['issues']

      if 'scheme' in service and service['scheme'] == 'http':
        # HTTP-only services must redirect to HTTPS
        if 'location' in service['response_headers']:
          for redirect in service['response_headers']['location']:
            if 'https://' not in redirect:
              issues.append("`location` header: HTTP service does not redirect to HTTPS")
              break
        else:
          issues.append("HTTP service does not redirect to HTTPS")

      if 'mandatory_headers' in self.recommendations:
        # compile a list of HTTP response headers deemed to be mandatory but which haven't been sent
        mandatory_headers = list(
          set(
            self.recommendations['mandatory_headers'] # mandatory headers
          ).difference(
            service['response_headers'].keys() # headers the server has sent
          )
        )

        if 'scheme' in service and service['scheme'] == 'http':
          try:
            # for HTTP-only services remove the STS header from the list of mandatory headers
            mandatory_headers.remove('strict-transport-security')
          except:
            # we received an error while trying to remove an element from the list of mandatory headers
            # this means the STS header was NOT in that list.
            # this further means that the server sent the STS header.
            # https://datatracker.ietf.org/doc/html/rfc6797#section-7.2
            issues.append("`strict-transport-security` header: an HSTS host must not include this header in responses conveyed over non-secure transport (i.e. HTTP)")
            del service['response_headers']['strict-transport-security']

        for missing_header in mandatory_headers:
          issues.append(f"`{missing_header}` header missing")

      for header_name, header_values in service['response_headers'].items():
        if header_name in self.recommendations['header']:
          for header_value in header_values:
            self._run_check(
              [ 'header', header_name ],
              header_value,
              issues
            )

      '''
      special cases: vulnerability scanners

      for example, Nikto does not list the response headers; instead it lists various vulnerabilities it found.

      TODO: what's the best way to tackle this?

      the parsers (for scanners like that) should collect those items in a dictionary named after the tool (inside the "service" dictionary).
      example for a Nikto parser:

      service = copy.deepcopy(SERVICE_SCHEMA)
      service["nikto"] = {}
      nikto = service["nikto"]
      nikto["issue_ID"] = "issue description"
      nikto["issue_foo"] = "bar"

      the recommendations config file (for these tools) contains a list of IDs we are interested in.
      '''

      if self.parser_name in self.recommendations and self.parser_name in service:
        for issue_ID, issue in service[self.parser_name].items():
          if issue_ID in self.recommendations[self.parser_name]:
            issues.append(issue)

    return services

  def _run_check(self, breadcrumbs, value, issues):
    names = []
    recommendation = self.recommendations

    for breadcrumb in breadcrumbs:
      recommendation = recommendation[breadcrumb]
      if 'name' in recommendation:
        names.append(recommendation['name'])

    match = True

    if 'regex' in recommendation:
      p = re.compile(recommendation['regex'])
      m = p.search(value)

      match = match and bool(m)

    if 'lower_bound' in recommendation:
      match = match and (int(value) >= recommendation['lower_bound'])

    if 'upper_bound' in recommendation:
      match = match and (int(value) <= recommendation['upper_bound'])

    if match and 'on_match' in recommendation:
      on_match = recommendation['on_match']
      self._handle_event(on_match, names, m, breadcrumbs, value, issues)

    if not match and 'on_mismatch' in recommendation:
      on_mismatch = recommendation['on_mismatch']
      self._handle_event(on_mismatch, names, None, breadcrumbs, value, issues)

  def _handle_event(self, event_handler, names, match, breadcrumbs, value, issues):
    if 'issue' in event_handler:
      issues.append(f"{' '.join(names)} {event_handler['issue']}")
      return

    if 'next' in event_handler:
      for n in event_handler['next']:
        if match and n in match.groupdict():
          value = match.group(n)

        self._run_check(
          [*breadcrumbs, n],
          value,
          issues
        )
