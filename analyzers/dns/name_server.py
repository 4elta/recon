import copy
import json
import pathlib
import re

from . import SERVICE_SCHEMA

class Parser:
  '''
  parse results of the `name_server` scanner.

  $ name_server --json "{result_file}.json" {address} 2>&1 | tee "{result_file}.log"
  '''

  name = 'name_server'
  file_type = 'json'

  def __init__(self):
    self.services = {}

  def parse_files(self, files):
    for path in files[self.file_type]:
      self.parse_file(path)

    return self.services

  def parse_file(self, path):
    with open(path) as f:
      result = json.load(f)

    identifier = result['address']
    if identifier in self.services:
      return

    service = copy.deepcopy(SERVICE_SCHEMA)
    service.update(result)
    self.services[identifier] = service
