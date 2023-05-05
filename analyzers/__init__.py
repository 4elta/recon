import importlib
import pathlib
import sys

class AbstractParser:

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
      self.parse_file(path)

    return self.services

  def parse_file(self, path):
    '''
    parse a specific file.
    this method has to be implemented by each concrete Parser class.
    '''
    pass

class AbstractAnalyzer:

  def __init__(self, name, recommendations):
    '''
    initialize the analyzer.
    this method may need to be extended by each concrete Analyzer class.
    '''

    self.name = name
    self.recommendations = recommendations
    self.services = []

  def set_parser(self, parser_name):
    '''
    set the parser that will be used to parse the results.
    '''

    module_path = pathlib.Path(
      pathlib.Path(__file__).resolve().parent,
      self.name,
      f'{parser_name}.py'
    )

    if not module_path.exists():
      sys.exit(f"unknown parser '{parser_name}'")

    self.parser_name = parser_name
    module = importlib.import_module(f'{__name__}.{self.name}.{parser_name}')
    self.parser = module.Parser()

  def analyze(self, files):
    '''
    analyze services based on some recommendations.
    this method has to be extended by each concrete Analyzer class
    '''

    if self.parser_name not in files:
      sys.exit("\nnothing to analyze")
