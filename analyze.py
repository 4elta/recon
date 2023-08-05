#!/usr/bin/env python3

import argparse
import csv
import importlib
import json
import pathlib
import re
import sys

try:
  # https://github.com/uiri/toml
  import toml
except:
  sys.exit("this script requires the 'toml' module.\nplease install it via 'pip3 install toml'.")

SUPPORTED_SERVICES = ['dns', 'ftp', 'http', 'isakmp', 'ntp', 'rdp', 'ssh', 'tls', ]

LANGUAGE = 'en'

def analyze_service(service, files, tool=None, recommendations_file=None, json_path=None, csv_path=None):
  if recommendations_file:
    if not recommendations_file.exists():
      sys.exit(f"the recommendations file '{recommendations_file}' does not exist!")
  else:
    recommendations_file = pathlib.Path(
      pathlib.Path(__file__).resolve().parent,
      "config",
      "recommendations",
      service,
      "default.toml"
    )
    if not recommendations_file.exists():
      sys.exit(f"the default recommendations file '{recommendations_file}' does not exist!")

  with open(recommendations_file, 'r') as f:
    recommendations = toml.load(f)

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

  if not issues_file.exists():
    sys.exit(f"the file '{issues_file}' does not exist!")

  with open(issues_file, 'r') as f:
    issue_templates = toml.load(f)

  affected_assets = []
  recommendations = []
  references = []
  info = []

  print("\n# evidence\n")
  print("The following hosts have been analyzed:\n")

  for asset in services.keys():
    print(f"* `{asset}`")

  print(f"\nThe following vulnerabilities and/or deviations from the recommended settings (`{recommendations_file}`) have been identified:")

  for asset, service in services.items():
    if not len(service['issues']):
      continue

    affected_assets.append(f"{asset}")

    print(f"\n## {asset}\n")

    for issue in service['issues']:
      issue.format(issue_templates)

      print(f"* {issue.description}")

      for recommendation in issue.recommendations:
        if recommendation not in recommendations:
          recommendations.append(recommendation)

      for reference in issue.references:
        if reference not in references:
          references.append(reference)

    # collect additional (debug) information
    if 'info' in service:
      for i in service['info']:
        if i not in info:
          info.append(i)

  if len(affected_assets):
    print("\n# affected assets\n")
    for asset in affected_assets:
      print(f"* `{asset}`")

  if len(recommendations):
    print("\n# recommendations\n")
    for recommendation in recommendations:
      print(f"* {recommendation}")

  if len(references):
    print("\n# references\n")
    for reference in references:
      print(f"* {reference}")

  if len(info):
    print("\n# additional info\n")
    for i in info:
      print(f"* {i}")

  if json_path:
    with open(json_path, 'w') as f:
      json.dump(services, f, indent=2)

  if csv_path:
    save_CSV(services, csv_path)

def get_files(directory, service):
  files = {}

  for path in directory.glob(f'**/services/{service}*'):
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

def save_CSV(services, path):
  delimiter = ','
  header = ['asset', 'issues']

  with open(path, 'w') as f:
    csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(header)

    for identifier, service in services.items():
      for issue in service['issues']:
        row = [identifier, issue.description]
        csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(row)

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
    files = get_files(args.input, args.service)

    global LANGUAGE
    LANGUAGE = args.language

    analyze_service(
      args.service,
      files,
      tool = args.tool,
      recommendations_file = args.recommendations,
      json_path = args.json,
      csv_path = args.csv
    )

def main():
  parser = argparse.ArgumentParser()

  parser.add_argument(
    'service',
    choices = ['?'] + SUPPORTED_SERVICES,
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
    '--json',
    metavar = 'path',
    type = pathlib.Path,
    help = "in addition to the analysis printed in Markdown to STDOUT, also save the analysis as a JSON document"
  )

  parser.add_argument(
    '--csv',
    metavar = 'path',
    type = pathlib.Path,
    help = "in addition to the analysis printed in Markdown to STDOUT, also save the analysis as a CSV document"
  )

  process(parser.parse_args())

if __name__ == '__main__':
  main()
