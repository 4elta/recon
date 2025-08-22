import importlib
import json
import logging
import pathlib
import sys

def parse_scan_name(scan_name):
  '''
  parse the name of a tool/scan (e.g. 'tool#some#tag')
  and extract its name ('tool') and tags ('some', 'tag')
  '''

  tags = scan_name.split('#')
  cleaned_scan_name = tags.pop(0)

  return (cleaned_scan_name, tags)

class Issue(dict):

  logger = logging.getLogger(__name__)

  def __init__(self, id, **values):
    '''
    initialize an issue:
    issue = Issue(123, a='42', b='bits')
    or:
    values = {"a": "42", "b": "bits"}
    issue = Issue(123, **values)
    '''

    self.id = id
    self.values = values

    self.description = None
    self.recommendations = []
    self.references = []

    dict.__init__(self, **values)

  def format(self, templates):
    issue_template = templates[self.id]

    self._format_description(issue_template['description'])

    if 'recommendations' in issue_template:
      self._format_recommendations(issue_template['recommendations'])

    if 'references' in issue_template:
      self._format_references(issue_template['references'])

  def _format_description(self, description):
    self.description = description.format(**self.values)
    self['description'] = self.description

  def _format_recommendations(self, recommendations):
    self.recommendations = []
    for recommendation in recommendations:
      formatted_recommendation = recommendation.format(**self.values)
      self.recommendations.append(formatted_recommendation)

    self['recommendations'] = self.recommendations

  def _format_references(self, references):
    self.references = []
    for reference in references:
      formatted_reference = reference.format(**self.values)
      self.references.append(formatted_reference)

    self['references'] = self.references

class AbstractParser:

  logger = logging.getLogger(__name__)

  def __init__(self):
    '''
    initialize the parser.
    this method has to be extended by each concrete Parser class.
    in particular, the `name` and `file_type` variables have to be set:

    self.name = 'name'
    self.file_type = 'xml'
    '''

    self.services = {}

  def parse_files(self, files):
    if self.file_type not in files:
      return self.services

    for path in files[self.file_type]:
      try:
        self.parse_file(path)
      except Exception as e:
        self.__class__.logger.warning(f"could not parse file: {e}")

    return self.services

  def parse_file(self, path):
    '''
    parse a specific file.
    this method has to be implemented by each concrete Parser class.
    '''

    self.__class__.logger.debug(f"parsing '{path}'")

    '''
    filename structure for most of the scans:
    <app protocol>,<transport protocol>,<port>,<scan name>.<ext>

    filename structure for scans of web services (HTTP, TLS):
    <app protocol>,<transport protocol>,<port>,<hostname>,<scan name>.<ext>

    filename structure for scans of services running on multiple ports (eg SMB):
    <app protocol>,<scan name>.<ext>
    '''

    filename = path.split('/')[-1]
    tokens = filename.split(',')

    self.application_protocol = tokens[0]

    if len(tokens) > 2:
      self.transport_protocol = tokens[1]
    else:
      self.transport_protocol = '_'

    self.__class__.logger.debug(f"application/transport protocol: '{self.application_protocol}/{self.transport_protocol}'")

class AbstractAnalyzer:

  logger = logging.getLogger(__name__)

  def __init__(self, name, recommendations):
    '''
    initialize the analyzer.
    '''

    self.__class__.logger.debug(f"initializing analyzer '{name}'")

    self.name = name
    self.parser_name = None
    self.recommendations = recommendations
    self.services = []

  def set_parser(self, parser_name):
    '''
    set the parser that will be used to parse the results.
    '''

    parser_name, _ = parse_scan_name(parser_name)

    self.__class__.logger.debug(f"setting parser to '{parser_name}'")

    module_path = pathlib.Path(
      pathlib.Path(__file__).resolve().parent,
      self.name,
      f'{parser_name}.py'
    )

    if not module_path.exists():
      raise RuntimeError(f"parser '{parser_name}' does not exist")

    self.__class__.logger.debug(f"parser module '{module_path}'")
    self.parser_name = parser_name

    module_name = f'{__name__}.{self.name}.{parser_name}'
    self.__class__.logger.debug(f"importing parser '{module_name}'")
    module = importlib.import_module(module_name)
    self.parser = module.Parser()

  def analyze(self, files):
    '''
    analyze services based on some recommendations.
    this method has to be extended by each concrete Analyzer class
    '''

    if not self.parser_name:
      self.__class__.logger.error("parser not configured!")
      raise RuntimeError("parser not configured")

    if not files:
      self.__class__.logger.warn("nothing to analyze")
      raise Warning("nothing to analyze")
