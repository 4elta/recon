#!/usr/bin/env python3

# run service-specific scans based on the result of Nmap service scans.

import argparse
import asyncio
from concurrent.futures import Executor, ThreadPoolExecutor, as_completed
import os
import pathlib
import random
import re
import string
import subprocess
import sys
import time

try:
  # https://rich.readthedocs.io/en/latest/index.html
  from rich.progress import (
    Progress,
    SpinnerColumn,
    TaskID,
  )
except:
  print("this script requires the 'rich' module.\nplease install it via 'pip3 install rich'.")
  sys.exit(1)

try:
  # https://github.com/uiri/toml
  import toml
except:
  print("this script requires the 'toml' module.\nplease install it via 'pip3 install toml'.")
  sys.exit(1)

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  print("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")
  sys.exit(1)

progress = Progress(
  SpinnerColumn(),
  "[progress.description]{task.description}",
  transient = True,
)

rootdir = os.path.dirname(os.path.realpath(__file__))

services_config_file = os.path.join(rootdir, "services.toml")
with open(services_config_file, 'r') as f:
  services_config = toml.load(f)

VERBOSE = False
DRY_RUN = False
OVERWRITE = False

class Service:
  def __init__(self, port, transport_protocol, application_protocol, description):
    self.port = int(port)
    self.transport_protocol = transport_protocol
    self.application_protocol = application_protocol
    self.description = description

class Target:
  def __init__(self, address, directory):
    self.address = address
    self.hostname = address
    self.directory = directory
    self.services = []
    self.scans = []
    self.lock = None

def log(msg):
  if VERBOSE:
    progress.console.log(msg)

def format(*args, frame_index=1, **kvargs):
  '''
  this function's purpose is to correctly format f-strings [1] (e.g. commands),
  defined in different frames (i.e. coroutines).

  [1]: https://docs.python.org/3/reference/lexical_analysis.html#f-strings
  '''

  frame = sys._getframe(frame_index)

  vals = {}

  vals.update(frame.f_globals)
  vals.update(frame.f_locals)
  vals.update(kvargs)

  return string.Formatter().vformat(' '.join(args), args, vals)

def stop(executor: Executor):
  task_ID = progress.add_task("stopping ... press ^C to kill running tasks")
  executor.shutdown(cancel_futures=True)
  progress.remove_task(task_ID)

def create_summary(target: Target):
  services_file = os.path.join(target.directory, 'services.md')
  with open(services_file, 'w') as f:
    for service in target.services:
      description = service.application_protocol
      if service.description:
        description = service.description

      f.write(f"* {service.port} ({service.transport_protocol}): `{description}`\n")

  services_file = os.path.join(target.directory, 'services.tex')
  with open(services_file, 'w') as f:
    f.write(r"\begin{center}" + "\n")
    f.write(r"\rowcolors{1}{white}{light-gray}" + "\n")
    f.write(r"\begin{tabular}{r c p{.75\linewidth}}" + "\n")
    f.write(r"\textbf{port} & \textbf{protocol} & \textbf{service} \\" + "\n")

    for service in target.services:
      description = service.application_protocol
      if service.description:
        description = service.description

      f.writelines(f"{service.port} & {service.transport_protocol} & {description} " + r"\\" + "\n")

    f.writelines(r"\end{tabular}" + "\n")
    f.writelines(r"\end{center}" + "\n")

async def run_command(description: str, command: str, patterns: list, target: Target):
  task_ID = progress.add_task(f"{description}")

  # make sure that the multiple coroutines don't write to the 'commands' file at the same time
  async with target.lock:
    log(command)
    with open(os.path.join(target.directory, 'commands.log'), 'a') as f:
      f.write(f"{command}\n")

  if DRY_RUN == False:
    # create/start the async process
    process = await asyncio.create_subprocess_shell(
      command,
      stdout = asyncio.subprocess.PIPE,
      stderr = asyncio.subprocess.PIPE,
      executable = '/bin/bash'
    )

    # parse STDOUT
    while True:
      line = await process.stdout.readline()
      if line:
        line = str(line.rstrip(), 'utf8', 'ignore')
        log(line)

        for pattern in patterns:
          match = re.search(pattern, line)
          if match:
            progress.console.print(f"{description}: \"{line.strip()}\"")
      else:
        break

    # wait for the process to finish
    await process.wait()

    if process.returncode != 0:
      error_msg = await process.stderr.read()
      error_msg = error_msg.decode().strip()
      progress.console.print(f"[red]{description}: {error_msg}")

  progress.remove_task(task_ID)
  progress.console.print(f"[green]{description}: finished")

async def scan_services(target: Target):
  # extract the target's address from the object
  # it's referenced like this in the scan configs
  address = target.address

  results_directory = os.path.join(target.directory, 'services')
  log(f"results directory: {results_directory}")
  os.makedirs(results_directory, exist_ok=True)

  tasks = []

  # iterate over each service scan configuration
  for service_name, service_config in services_config.items():
    service_patterns = service_config['patterns'] if 'patterns' in service_config else ['.+']

    for scan_name, scan in service_config['scans'].items():
      scan_command = scan['command']
      scan_patterns = scan['patterns'] if 'patterns' in scan else []

      # iterate over the services found to be running on the target
      for service in target.services:
        transport_protocol = service.transport_protocol
        port = service.port
        application_protocol = service.application_protocol

        # special case for HTTP/HTTPS service
        scheme = 'http'
        hostname = target.hostname
        tls = False

        if application_protocol.startswith('ssl|') or application_protocol.startswith('tls|'):
          tls = True

        if 'http' in application_protocol and tls:
          scheme = 'https'

        result_file = os.path.join(results_directory, f'{service_name}-{scan_name}.log')
        description = f"{address}: {service_name}: {scan_name}"

        # run scan only if result file does not yet exist or "overwrite_results" flag is set
        if (os.path.isfile(result_file) and not OVERWRITE):
          continue

        # try to match the service with any of the scan config's service pattern
        match = False

        for service_pattern in service_patterns:
          if re.search(service_pattern, application_protocol):
            match = True
            break

        if not match:
          continue

        # make sure to not run scans targeting a specific service (group) multiple times
        if 'run_once' in scan and scan['run_once'] == True:
          log(description)
          scan_tuple = (service_name, scan_name)
          if scan_tuple in target.scans:
            log("[orange]this scan should only be run once")
            continue
          else:
            target.scans.append(scan_tuple)
        else:
          result_file = os.path.join(results_directory, f'{service_name}-{transport_protocol}-{port}-{scan_name}.log')
          description = f"{address}: {service_name}: {transport_protocol}/{port}: {scan_name}"
          log(description)
          scan_tuple = (transport_protocol, port, application_protocol, service_name, scan_name)
          if scan_tuple in target.scans:
            log("[orange]this scan appears to have already been queued")
            continue
          else:
            target.scans.append(scan_tuple)

        # run the scan
        tasks.append(asyncio.create_task(run_command(description, format(scan_command), scan_patterns, target)))

  for task in tasks:
    await task

def scan_target(target: Target):
  #task_ID = progress.add_task(target.address)

  # create directory
  os.makedirs(target.directory, exist_ok=True)

  # sort the target's services based on its port
  target.services.sort(key=lambda service: service.port)

  # create summary to be included in the LaTeX/Markdown report
  create_summary(target)

  # perform service-specific scans
  asyncio.run(scan_services(target))

  #progress.remove_task(task_ID)
  progress.console.print(f"[bold green]{target.address}: finished")

def parse_result_file(base_directory, result_file):
  targets = {}

  # https://nmap.org/book/nmap-dtd.html
  # nmaprun
  #   host
  #     address ("addr")
  #     hostnames
  #       hostname ("name", type="user")
  #     ports
  #       port (protocol, portid)
  #         state (state="open")
  #         service (name, product, version, extrainfo, tunnel, )

  nmaprun = defusedxml.ElementTree.parse(result_file).getroot()

  for host in nmaprun.iter('host'):
    address = host.find('address').get('addr')

    if address not in targets:
      target = Target(address, os.path.join(base_directory, address))
      targets[address] = target
    else:
      target = targets[address]

    try:
      target.hostname = host.findall("hostnames/hostname[@type='user']")[0].get('name')
    except:
      pass

    log(f"{address} ({target.hostname})")

    for port in host.iter('port'):
      if port.find('state').get('state') != 'open':
        continue

      transport_protocol = port.get('protocol')
      port_ID = port.get('portid')

      service = port.find('service')
      if service is None:
        application_protocol = 'unknown'
        description = 'unknown'
      else:
        application_protocol = service.get('name')
        if service.get('tunnel'):
          application_protocol = service.get('tunnel') + '|' + application_protocol

        description = service.get('product')
        if service.get('version'):
          description += f" {service.get('version')}"
        if service.get('extrainfo'):
          description += f" {service.get('extrainfo')}"

      target.services.append(Service(port_ID, transport_protocol, application_protocol, description))
      log(f"{transport_protocol}, {port_ID}: {application_protocol}: {description}")

  return targets

def process(args):
  global VERBOSE
  VERBOSE = args.verbose

  global DRY_RUN
  DRY_RUN = args.dry_run

  global OVERWRITE
  OVERWRITE = args.overwrite_results

  with progress:
    base_directory = os.path.abspath(args.output)
    log(f"base directory: '{base_directory}'")
    os.makedirs(base_directory, exist_ok=True)

    input_file = os.path.abspath(args.input)
    if os.path.isfile(input_file) != True:
      progress.console.print(f"[bold red]input file '{input_file}' does not exist!")
      exit(1)

    # parse Nmap result file of the service scan (XML)
    targets = parse_result_file(base_directory, args.input)
    log(f"parsed {len(targets)} targets")

    with ThreadPoolExecutor(max_workers=args.concurrent) as executor:
      futures = []
      for address, target in targets.items():
        # a lock is needed so the coroutines don't overwrite each other
        # when writing to the 'commands' file
        target.lock = asyncio.Lock()

        futures.append(executor.submit(scan_target, target))

      try:
        for future in as_completed(futures):
          future.result()
        progress.console.print("[bold green]done")
      except KeyboardInterrupt:
        progress.console.print("[bold red]aborted by user")
        stop(executor)

def main():
  parser = argparse.ArgumentParser()

  parser.add_argument('-i', '--input', type=pathlib.Path, default='services.xml', help="the result file of the Nmap service scan")
  parser.add_argument('-o', '--output', type=pathlib.Path, default='./recon', help="where the results are stored")
  parser.add_argument('-c', '--concurrent', type=int, default=3, help="how many targets should be scanned concurrently")
  parser.add_argument('-v', '--verbose', action='store_true', help="show additional info including all output of all scans")
  parser.add_argument('-n', '--dry_run', action='store_true', help="do not run any command; just create/update the 'commands.log' file")
  parser.add_argument('-y', '--overwrite_results', action='store_true', help="overwrite existing result files")

  process(parser.parse_args())

if __name__ == '__main__':
  main()
