#!/usr/bin/env python3

import argparse
import csv
import importlib
import jinja2
import json
import logging
import pathlib
import re
import sys
import tomllib as toml

#LOGGER = logging.getLogger('recon.analyzer')
LOGGER = logging.getLogger(__name__)

ANALYZERS_DIR = pathlib.Path(
  pathlib.Path(__file__).resolve().parent,
  "analyzers"
)

SUPPORTED_SERVICES = []
for path in ANALYZERS_DIR.iterdir():
  if path.is_dir() and not path.name.startswith('__'):
    SUPPORTED_SERVICES.append(path.name)

LANGUAGE = 'en'
SUPPORTED_FORMATS = ['md', 'json', 'csv']


def analyze_service(service, files, recommendations_file, tool=None):
  with open(recommendations_file, 'rb') as f:
    recommendations = toml.load(f)

  LOGGER.debug(f"importing 'analyzers.{service}'")
  module = importlib.import_module(f'analyzers.{service}')
  analyzer = module.Analyzer(service, recommendations)

  if tool:
    analyzer.set_parser(tool)

  services = analyzer.analyze(files)

  issues_file = pathlib.Path(
    pathlib.Path(__file__).resolve().parent,
    "config",
    "issues",
    service,
    f"{LANGUAGE}.toml"
  )

  LOGGER.info(f"loading issues file '{issues_file}'")
  if not issues_file.exists():
    LOGGER.error("issues file does not exist!")
    sys.exit(f"the file '{issues_file}' does not exist!")

  with open(issues_file, 'rb') as f:
    issue_templates = toml.load(f)

  affected_assets = {}
  issues = {}
  recommendations = []
  references = []
  info = []

  for asset, service in services.items():
    if len(service['issues']) == 0:
      continue

    affected_assets[asset] = []

    for issue in service['issues']:
      issue.format(issue_templates)

      for recommendation in issue.recommendations:
        if recommendation not in recommendations:
          recommendations.append(recommendation)

      for reference in issue.references:
        if reference not in references:
          references.append(reference)

      affected_assets[asset].append(issue.description)

      if issue.description not in issues:
        issues[issue.description] = []

      issues[issue.description].append(asset)

    # collect additional (debug) information
    if 'info' in service:
      for i in service['info']:
        if i not in info:
          info.append(i)

  return {
    'services': services,
    'affected_assets': affected_assets,
    'issues': issues,
    'recommendations': recommendations,
    'references': references,
    'additional_info': info,
  }

def get_files(directory, service):
  files = {}

  for path in directory.glob(f'*/{service}*'):
    suffix = path.suffix[1:]
    stem = path.stem # the final path component, w/o its suffix
    tool = stem.split(',')[-1]

    if tool not in files:
      files[tool] = {}

    if suffix not in files[tool]:
      files[tool][suffix] = []

    if path not in files[tool][suffix]:
      files[tool][suffix].append(str(path))

  return files

def render_CSV(services):
  delimiter = ','
  header = ['asset', 'issues']

  csv.writer(sys.stdout, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(header)

  for identifier, service in services.items():
    for issue in service['issues']:
      row = [identifier, issue.description]
      csv.writer(sys.stdout, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(row)

def process(args):

  if not args.input.exists():
    sys.exit(f"the specified directory '{args.input}' does not exist!")

  if args.service == '?':
    services = {}
    for service in SUPPORTED_SERVICES:
      files = get_files(args.input, service)
      if len(files):
        services[service] = files.keys()

    print("scan results relating to the following services are available for analysis.")
    print("the name of the scanner is shown in parenthesis.\n")

    for service, tools in services.items():
      print(f"* {service} ({', '.join(tools)})")
  else:
    logging.basicConfig(
      format = '%(levelname)s: %(message)s',
      filename = f'analyzer-{args.service}.log',
      filemode = 'w',
      encoding = 'utf-8',
      level = logging.DEBUG
    )

    LOGGER.debug(f"requested to analyze '{args.service}'")
    files = get_files(args.input, args.service)

    global LANGUAGE
    LANGUAGE = args.language
    LOGGER.debug(f"using language '{LANGUAGE}'")

    if args.recommendations:
      recommendations_file = args.recommendations
      LOGGER.info(f"user specified recommendations file: '{args.recommendations}'")
      if not recommendations_file.exists():
        LOGGER.error("the recommendations file does not exist!")
        sys.exit(f"the recommendations file '{recommendations_file}' does not exist!")
    else:
      recommendations_file = pathlib.Path(
        pathlib.Path(__file__).resolve().parent,
        "config",
        "recommendations",
        args.service,
        "default.toml"
      )
      LOGGER.info(f"using default recommendations file: '{recommendations_file}'")
      if not recommendations_file.exists():
        LOGGER.error("the recommendations file does not exist!")
        sys.exit(f"the default recommendations file '{recommendations_file}' does not exist!")

    analysis = analyze_service(
      args.service,
      files,
      recommendations_file,
      tool = args.tool
    )

    analysis['recommendations_file'] = recommendations_file

    render_analysis = True

    if args.template:
      LOGGER.info(f"user specified template file: '{args.template}'")
      if not args.template.exists():
        LOGGER.error("the template file does not exist!")
        sys.exit(f"the specified template file '{args.template}' does not exist!")
      else:
        template_file = args.template.resolve()
    else:
      LOGGER.info(f"user specified format: '{args.fmt}'")
      if args.fmt == 'json':
        render_analysis = False
        print(json.dumps(analysis['services']))
      elif args.fmt == 'csv':
        render_analysis = False
        render_CSV(analysis['services'])
      else:
        template_file = pathlib.Path(
          pathlib.Path(__file__).resolve().parent,
          "config",
          "templates",
          f"default.{LANGUAGE}.md"
        )
        LOGGER.info(f"using default template file: '{template_file}'")
        if not template_file.exists():
          LOGGER.error("the template file does not exist!")
          sys.exit(f"the default template file '{template_file}' does not exist!")

    if render_analysis:
      env = jinja2.Environment(
        loader = jinja2.FileSystemLoader(template_file.parent),
        trim_blocks = True,
        autoescape = False
      )

      template = env.get_template(template_file.name)
      rendered_analysis = template.render(analysis).strip()

      print(rendered_analysis)

def main():
  parser = argparse.ArgumentParser(
    description = "Analyze and summarize the results of specific tools previously run by the scanner of the recon tool suite (i.e. 'scan')."
  )

  parser.add_argument(
    'service',
    choices = ['?'] + sorted(SUPPORTED_SERVICES),
    help = "specify the service that should be analyzed. use '?' to list services available for analysis."
  )

  parser.add_argument(
    '-t', '--tool',
    metavar = 'name',
    help = "specify the tool whose results are to be parsed"
  )

  parser.add_argument(
    '-r', '--recommendations',
    metavar = 'path',
    type = pathlib.Path,
    help = "path to the recommendations document (default: '/path/to/recon/config/recommendations/<service>/default.toml')"
  )

  parser.add_argument(
    '-i', '--input',
    metavar = 'path',
    type = pathlib.Path,
    default = './recon',
    help = "path to the root directory that holds the results to be analysed (default: './recon')"
  )

  parser.add_argument(
    '-l', '--language',
    metavar = 'code',
    default = LANGUAGE,
    help = f"specify the language in which the analysis should be printed (default: '{LANGUAGE}')"
  )

  parser.add_argument(
    '-f', '--format',
    dest = 'fmt',
    metavar = 'code',
    choices = SUPPORTED_FORMATS,
    default = SUPPORTED_FORMATS[0],
    help = f"specify the output format of the analysis (choices: {SUPPORTED_FORMATS}; default: '{SUPPORTED_FORMATS[0]}')"
  )

  parser.add_argument(
    '--template',
    metavar = 'path',
    type = pathlib.Path,
    help = "path to the Jinja2 template for the analysis; this option overrides '-f/--format'"
  )

  process(parser.parse_args())

if __name__ == '__main__':
  main()
