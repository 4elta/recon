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

  def set_tool(self, tool):
    '''
    filter the results (based on the tool) that are to be analyzed.
    '''

    module_path = pathlib.Path(
      pathlib.Path(__file__).resolve().parent,
      self.name,
      f'{tool}.py'
    )

    if not module_path.exists():
      sys.exit(f"unknown tool '{tool}'")

    self.tool = tool
    module = importlib.import_module(f'{__name__}.{self.name}.{tool}')
    self.parser = module.Parser()

  def analyze(self, files):
    '''
    analyze services based on some recommendations.
    this method has to be extended by each concrete Analyzer class
    '''

    if self.tool not in files:
      return
