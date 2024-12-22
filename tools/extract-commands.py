#!/usr/bin/env python3

import argparse
import csv
import pathlib

def process(args):
  with open(args.input, newline='') as f:
    reader = csv.DictReader(f, delimiter=args.delimiter, quoting=csv.QUOTE_MINIMAL)
    for row in reader:
      print(row['command'])

def main():
  parser = argparse.ArgumentParser(
    description = "Extract the commands from the command log (i.e. 'commands.csv')."
  )

  parser.add_argument(
    'input',
    metavar = 'path',
    type = pathlib.Path,
    help = "path to the command log (i.e. 'commands.csv')"
  )

  parser.add_argument(
    '-d', '--delimiter',
    metavar = 'character',
    help = "character used to delimit columns in the command log (default: ',')",
    default = ','
  )

  process(parser.parse_args())

if __name__ == '__main__':
  main()
