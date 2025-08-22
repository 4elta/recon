import json
import re

from .. import Issue, AbstractAnalyzer

SERVICE_SCHEMA = {
  'scheme': None,
  'host': None,
  'port': None,
  'response_headers': {},
  'response_body': None,
  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files)
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():

      issues = service['issues']

      if 'scheme' in service and service['scheme'] == 'http':
        # HTTP-only services must redirect to HTTPS
        if 'location' in service['response_headers']:
          for redirect in service['response_headers']['location']:
            if 'https://' not in redirect:
              issues.append(Issue("missing redirect to HTTPS"))
              break
        else:
          issues.append(Issue("missing redirect to HTTPS"))

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
            issues.append(Issue("STS header over HTTP"))
            del service['response_headers']['strict-transport-security']

        for missing_header in mandatory_headers:
          issues.append(
            Issue(
              "mandatory header missing",
              header = missing_header
            )
          )

      for header_name, header_values in service['response_headers'].items():
        if header_name in self.recommendations['header']:
          for header_value in header_values:
            self._run_check(
              ( 'header', header_name ),
              header_value,
              issues
            )

      if service['response_body']:
        for html_elem in self.recommendations['body']:
          self._run_check(
            ( 'body', html_elem ),
            service['response_body'],
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
    recommendation = self.recommendations

    # recurse down the recommendations:
    # 'header'.<header name>.<...>.<check ID>
    for check in breadcrumbs:
      recommendation = recommendation[check]

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
      self._handle_event(on_match, value, breadcrumbs, issues, match=m)

    if not match and 'on_mismatch' in recommendation:
      on_mismatch = recommendation['on_mismatch']
      self._handle_event(on_mismatch, value, breadcrumbs, issues)

  def _handle_event(self, event_handler, value, breadcrumbs, issues, match=None):
    if 'issue' in event_handler:
      issue_id = event_handler['issue'].pop('id', None)
      if issue_id:
        issues.append(
          Issue(
            issue_id,
            value = value,
            **event_handler['issue']
          )
        )

    if 'next' in event_handler:
      for next_check in event_handler['next']:
        if match:
          if next_check in match.groupdict():
            value = match.group(next_check)
          elif 'value' in match.groupdict():
            value = match.group('value')

        if '.' in next_check:
          self._run_check(
            next_check.split('.'),
            value,
            issues
          )
        else:
          self._run_check(
            (*breadcrumbs, next_check),
            value,
            issues
          )
