#!/usr/bin/env python3

import argparse
import copy
import json
import pathlib
import re

try:
  # https://github.com/uiri/toml
  import toml
except:
  sys.exit("this script requires the 'toml' module.\nplease install it via 'pip3 install toml'.")

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
      #files[tool][suffix].append(path)
      files[tool][suffix].append(str(path))

  return files

def process(args):
  if not args.input.exists():
    sys.exit(f"the specified directory '{base_dir}' does not exist!")

  if not args.recommendations.exists():
    sys.exit(f"the recommendations file '{args.recommendations}' does not exist!")

  with open(args.recommendations, 'r') as f:
    recommendations = toml.load(f)

  #print(json.dumps(recommendations, indent=2))

  if not args.input.exists():
    sys.exit(f"directory '{args.input}' does not exist")

  files = get_files(args.input, args.service)
  #print(json.dumps(files, indent=2))

  analyzer = None
  services = {}

  if args.service == 'tls':
    import analyzers.tls
    analyzer = analyzers.tls.Analyzer(args.tool, recommendations)
  elif args.service == 'ssh':
    import analyzers.ssh
    analyzer = analyzers.ssh.Analyzer(args.tool, recommendations)

  if analyzer:
    services = analyzer.analyze(files)

  affected_assets = []

  for asset, service in services.items():
    if not len(service['issues']):
      continue

    affected_assets.append(f"{asset}")

    print(f"\n## {asset}\n")

    print(f"Vulnerabilities and/or deviations from the recommended settings (`{args.recommendations.name}`):\n")

    for issue in service['issues']:
      print(f"* {issue}")

  print(f"\n# affected assets\n")

  for asset in affected_assets:
    print(f"* `{asset}`")

  if args.json:
    with open(args.json, 'w') as f:
      json.dump(services, f, indent=2)

  if args.csv:
    analyzer.save_CSV(args.csv, args.tool)

def main():
  parser = argparse.ArgumentParser()

  parser.add_argument(
    'service',
    choices = ['tls', 'ssh'],
    help = "specify the service/protocol whose results are to be analyzed"
  )

  parser.add_argument(
    'tool',
    help = "specify the tool whose results are to be analyzed"
  )

  parser.add_argument(
    'recommendations',
    type = pathlib.Path,
    help = "path to the recommendations document (e.g.: '/path/to/recon/config/recommendations/tls/mozilla-intermediate.toml')"
  )

  parser.add_argument(
    '-i', '--input',
    type = pathlib.Path,
    default = './recon',
    help = "path to the root directory that holds the results to be analysed (default: './recon')"
  )

  parser.add_argument(
    '--json',
    type = pathlib.Path,
    help = "in addition to the analysis printed in Markdown to STDOUT, also save the analysis as a JSON document"
  )

  parser.add_argument(
    '--csv',
    type = pathlib.Path,
    help = "in addition to the analysis printed in Markdown to STDOUT, also save the analysis as a CSV document"
  )

  process(parser.parse_args())

if __name__ == '__main__':
  main()
