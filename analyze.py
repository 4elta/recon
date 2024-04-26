#!/usr/bin/env python3

import argparse
import csv
import importlib
import json
import pathlib
import re
import sys
import tomllib as toml

ANALYZERS_DIR = pathlib.Path(
  pathlib.Path(__file__).resolve().parent,
  "analyzers"
)

SUPPORTED_SERVICES = []
for path in ANALYZERS_DIR.iterdir():
  if path.is_dir():
    SUPPORTED_SERVICES.append(path.name)

LANGUAGE = 'en'

def _group_by_asset(assets):
  for asset, issues in assets.items():
    print(f"\n## {asset}\n")

    for issue in issues:
      print(f"* {issue}")

def _group_by_issue(issues):
  for description, assets in {key:issues[key] for key in sorted(issues.keys())}.items():
    print(f"\n## {description}")

    print("\nThis issue has been found in the following assets:\n")

    for asset in assets:
      print(f"* `{asset}`")

def analyze_service(service, files, tool=None, recommendations_file=None, group_by_issue=False, json_path=None, csv_path=None):
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

  with open(recommendations_file, 'rb') as f:
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

  with open(issues_file, 'rb') as f:
    issue_templates = toml.load(f)

  affected_assets = {}
  issues = {}
  recommendations = []
  references = []
  info = []

  print("\n# evidence\n")
  print("The following hosts have been analyzed:\n")

  for asset in services.keys():
    print(f"* `{asset}`")

  print(f"\nThe following vulnerabilities and/or deviations from the recommended settings (`{recommendations_file}`) have been identified:")

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

  if group_by_issue:
    _group_by_issue(issues)
  else:
    _group_by_asset(affected_assets)

  if len(affected_assets):
    print("\n# affected assets\n")
    for asset in affected_assets.keys():
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
      group_by_issue = args.group_by_issue,
      json_path = args.json,
      csv_path = args.csv
    )

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
    '-g', '--group_by_issue',
    help = "group by issue and list all assets affected by it instead of grouping by asset and listing all its issues",
    action = 'store_true'
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
