#!/usr/bin/env python3

import argparse
import csv
import datetime
import importlib
import io
import jinja2
import json
import logging
import pathlib
import sys
import tomllib as toml

import analyzers

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


def analyze_service(service, files, recommendations_file, tool):
  with open(recommendations_file, 'rb') as f:
    recommendations = toml.load(f)

  LOGGER.debug(f"importing 'analyzers.{service}'")
  module = importlib.import_module(f'analyzers.{service}')
  analyzer = module.Analyzer(service, recommendations)
  analyzer.set_parser(tool)

  services = analyzer.analyze(files)

  issues_file = pathlib.Path(
    pathlib.Path(__file__).resolve().parent,
    "config",
    "issues",
    service,
    f"{LANGUAGE}.toml"
  )

  LOGGER.debug(f"loading issues file '{issues_file}'")
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

def get_files(directory, service, scan_name_filter=None):
  files = {}

  for path in directory.glob(f'*/{service}*'):
    suffix = path.suffix[1:]
    stem = path.stem # the final path component, w/o its suffix
    scan_name = stem.split(',')[-1]

    if scan_name_filter and scan_name_filter != scan_name:
      continue

    if scan_name not in files:
      files[scan_name] = {}

    if suffix not in files[scan_name]:
      files[scan_name][suffix] = []

    if path not in files[scan_name][suffix]:
      files[scan_name][suffix].append(str(path))

  return files

def render_CSV(services):
  delimiter = ','
  header = ['asset', 'issues']

  output = io.StringIO()

  csv.writer(output, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(header)

  for identifier, service in services.items():
    for issue in service['issues']:
      row = [identifier, issue.description]
      csv.writer(output, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(row)

  rendered_analysis = output.getvalue()

  output.close()

  return rendered_analysis

def process(args):
  if not args.input.exists():
    sys.exit(f"the specified directory '{args.input}' does not exist!")

  services = {}
  for service in SUPPORTED_SERVICES:
    files = get_files(args.input, service)
    if len(files):
      services[service] = files.keys()

  if len(services) == 0:
    sys.exit("no scan results available for analysis.")

  if args.service and args.service not in services.keys():
    sys.exit("nothing to analyze")

  if args.config:
    config_file_path = args.config
    if not config_file_path.exists():
      sys.exit(f"the specified configuration file '{config_file_path}' does not exist!")
  else:
    config_file_path = pathlib.Path(
      pathlib.Path(__file__).resolve().parent,
      "config",
      "analyzer.toml"
    )
    if not config_file_path.exists():
      sys.exit(f"the default configuration file '{config_file_path}' does not exist!")

  with open(config_file_path, 'rb') as f:
    config = toml.load(f)

  selected_tags = []
  if args.scan:
    args.scan, selected_tags = analyzers.parse_scan_name(args.scan)

  potential_analyses = {}
  number_of_potential_analyses = 0
  for service, scan_names in services.items():
    if args.service and service != args.service:
      continue

    default_parser = config['default_parser'][service]

    for scan_name in scan_names:
      cleaned_scan_name, tags = analyzers.parse_scan_name(scan_name)

      if args.scan and args.scan != cleaned_scan_name:
        continue

      if args.service and not args.scan and default_parser != cleaned_scan_name:
        continue

      if args.scan and not selected_tags and tags:
        continue

      # make sure that all selected tags are present in this scan name's tags
      intersection = [t for t in selected_tags if t in tags]
      if selected_tags != intersection:
        continue

      if service not in potential_analyses:
        potential_analyses[service] = []

      if scan_name not in potential_analyses[service]:
        potential_analyses[service].append(scan_name)
        number_of_potential_analyses += 1

  if number_of_potential_analyses == 0:
    sys.exit("nothing to analyze")

  if number_of_potential_analyses > 1 and not args.output:
    print("scan results relating to the following services (along with the name of the tool/scan) are available for analysis:\n")

    for service, scan_names in dict(sorted(potential_analyses.items())).items():
      print(f"* {service}: {', '.join(sorted(scan_names))}")

    print(f"\nif you want to batch analyze these results, specify an output directory ('-o').")
    return

  timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

  logging.basicConfig(
    format = '%(levelname)s: %(message)s',
    filename = f'analyzer_{timestamp}.log',
    filemode = 'w',
    encoding = 'utf-8',
    level = logging.DEBUG
  )

  output_directory = None
  analysis_file = None
  batch_mode = (args.output and number_of_potential_analyses > 1)

  if batch_mode:
    LOGGER.debug("batch mode")

  if args.output:
    output_directory = args.output.resolve()
    LOGGER.info(f"user specified output directory: '{output_directory}'")
    output_directory.mkdir(exist_ok=True)

  if not args.service:
    if args.recommendations:
      LOGGER.info("no service selected: ignoring recommendation file")
    args.recommendations = None

  global LANGUAGE
  LANGUAGE = args.language
  LOGGER.info(f"using language '{LANGUAGE}'")

  if args.recommendations:
    recommendations_file = args.recommendations
    LOGGER.info(f"user specified recommendations file: '{args.recommendations}'")
    if not recommendations_file.exists():
      LOGGER.error("the recommendations file does not exist!")
      sys.exit(f"the recommendations file '{recommendations_file}' does not exist!")

  template_file = None

  if args.template:
    LOGGER.info(f"user specified template file: '{args.template}'")
    if not args.template.exists():
      LOGGER.error("the template file does not exist!")
      sys.exit(f"the specified template file '{args.template}' does not exist!")
    else:
      template_file = args.template.resolve()
  else:
    LOGGER.info(f"using output format: '{args.fmt}'")
    if args.fmt not in ('json', 'csv'):
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

    if template_file:
      env = jinja2.Environment(
        loader = jinja2.FileSystemLoader(template_file.parent),
        trim_blocks = True,
        autoescape = False
      )

      template = env.get_template(template_file.name)

  for service, scan_names in potential_analyses.items():
    LOGGER.info(f"analyzing service '{service}' ...")

    if not args.recommendations:
      recommendations_file = pathlib.Path(
        pathlib.Path(__file__).resolve().parent,
        "config",
        "recommendations",
        service,
        "default.toml"
      )

      LOGGER.info(f"using default recommendations file: '{recommendations_file}'")

      if not recommendations_file.exists():
        LOGGER.error("the recommendations file does not exist!")
        if batch_mode:
          continue
        else:
          sys.exit(f"the recommendations file does not exist!")

    for scan_name in scan_names:
      LOGGER.info(f"selecting tool/scan '{scan_name}' ...")

      files = get_files(args.input, service, scan_name)[scan_name]

      try:
        LOGGER.info("start analysis ...")
        analysis = analyze_service(
          service,
          files,
          recommendations_file,
          scan_name
        )
      except RuntimeError as error:
        LOGGER.error(error)
        if batch_mode:
          print(error, file=sys.stderr)
          continue
        else:
          sys.exit(error)
      except Warning as warning:
        LOGGER.warning(warning)
        print(warning, file=sys.stderr)
        continue

      if output_directory:
        analysis_file = pathlib.Path(
          output_directory,
          f"{service},{scan_name}.{args.fmt}"
        )

      analysis['recommendations_file'] = recommendations_file

      LOGGER.debug("rendering analysis ...")

      if template_file:
        rendered_analysis = template.render(analysis).strip()
      elif args.fmt == 'json':
        rendered_analysis = json.dumps(analysis['services']).strip()
      elif args.fmt == 'csv':
        rendered_analysis = render_CSV(analysis['services']).strip()

      if analysis_file:
        LOGGER.info(f"writing analysis to '{analysis_file}' ...")
        with open(analysis_file, 'w') as f:
          f.write(rendered_analysis)
      else:
        print(rendered_analysis)


def main():
  parser = argparse.ArgumentParser(
    description = "Analyze and summarize the results of specific tools previously run by the scanner of the recon tool suite (i.e. 'scan')."
  )

  parser.add_argument(
    '-c', '--config',
    metavar = 'path',
    type = pathlib.Path,
    help = "path to the analyzer configuration file (default: '/path/to/recon/config/analyzer.toml')"
  )

  parser.add_argument(
    '-s', '--service',
    metavar = 'code',
    choices = sorted(SUPPORTED_SERVICES),
    help = f"service that should be analyzed (choices: {sorted(SUPPORTED_SERVICES)})"
  )

  parser.add_argument(
    '-S', '--scan',
    metavar = 'name',
    help = "name of the tool/scan whose results should be parsed"
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
    help = f"language of the analysis (default: '{LANGUAGE}')"
  )

  parser.add_argument(
    '-f', '--format',
    dest = 'fmt',
    metavar = 'code',
    choices = SUPPORTED_FORMATS,
    default = SUPPORTED_FORMATS[0],
    help = f"format of the analysis (choices: {sorted(SUPPORTED_FORMATS)}; default: '{SUPPORTED_FORMATS[0]}')"
  )

  parser.add_argument(
    '--template',
    metavar = 'path',
    type = pathlib.Path,
    help = "path to the Jinja2 template for the analysis; this option overrides '-f/--format'"
  )

  parser.add_argument(
    '-o', '--output',
    metavar = 'path',
    type = pathlib.Path,
    help = "path to the directory where the analysis result(s) will be saved"
  )

  process(parser.parse_args())

if __name__ == '__main__':
  main()
