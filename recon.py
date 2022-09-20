#!/usr/bin/env python3

# run service-specific scans based on the result of Nmap service scans.

import argparse
import asyncio
from concurrent.futures import Executor, ThreadPoolExecutor, as_completed
import csv
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
  sys.exit("this script requires the 'rich' module.\nplease install it via 'pip3 install rich'.")

try:
  # https://github.com/uiri/toml
  import toml
except:
  sys.exit("this script requires the 'toml' module.\nplease install it via 'pip3 install toml'.")

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

progress = Progress(
  SpinnerColumn(),
  "[progress.description]{task.description}",
  transient = True,
)

class Service:
  def __init__(self, port, transport_protocol, application_protocol, description):
    self.port = int(port)
    self.transport_protocol = transport_protocol
    self.application_protocol = application_protocol
    self.description = description

class Target:
  def __init__(self, address, directory):
    self.address = address
    self.hostnames = []
    self.directory = directory
    self.services = []
    self.scans = {}
    self.semaphore = None # limiting the number of concurrently running scans

class Scan:
  def __init__(self, service, name, command, patterns, run_once):
    self.service = service
    self.name = name
    self.command = command
    self.patterns = patterns
    self.run_once = run_once

class Command:
  def __init__(self, description, string, patterns):
    self.description = description
    self.string = string
    self.patterns = patterns

class CommandLog:

  path = None
  lock = None # ensures that only a single thread can write to the commands log

  @classmethod
  def init(cls, path, lock, header):
    cls.path = path
    cls.lock = lock

    with open(cls.path, 'w') as f:
      csv.writer(f, delimiter=',', quoting=csv.QUOTE_MINIMAL).writerow(header)

  @classmethod
  async def add_entry(cls, entry):
    async with cls.lock:
      with open(cls.path, 'a') as f:
        csv.writer(f, delimiter=',', quoting=csv.QUOTE_MINIMAL).writerow(entry)

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

def stop_exucutor(executor: Executor):
  
  task_ID = progress.add_task("stopping ... press ^C to kill running tasks")
  executor.shutdown(cancel_futures=True)
  progress.remove_task(task_ID)

def create_summary(target: Target):
  
  services_file = pathlib.Path(target.directory, 'services.md')
  with open(services_file, 'w') as f:
    for service in target.services:
      description = service.application_protocol
      if service.description:
        description = service.description

      f.write(f"* {service.port} ({service.transport_protocol}): `{description}`\n")

  services_file = pathlib.Path(target.directory, 'services.tex')
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

async def run_command(command: Command, target: Target):

  # make sure that only a specific number of scans are running per target
  async with target.semaphore:
    task_ID = progress.add_task(f"{command.description}")

    log(command.string)

    timestamp_start = time.time()
    return_code = 0

    if not DRY_RUN:
      # create/start the async process
      process = await asyncio.create_subprocess_shell(
        command.string,
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

          for pattern in command.patterns:
            match = re.search(pattern, line)
            if match:
              progress.console.print(f"{command.description}: \"{line.strip()}\"")
        else:
          break

      # wait for the process to finish
      await process.wait()

      return_code = process.returncode
      
      if process.returncode != 0:
        error_msg = await process.stderr.read()
        error_msg = error_msg.decode().strip()
        progress.console.print(f"[red]{command.description}: {error_msg}")

    timestamp_completion = time.time()

    await CommandLog.add_entry([timestamp_start, timestamp_completion, command.string, return_code])
    
    progress.remove_task(task_ID)
    progress.console.print(f"[green]{command.description}: finished")

def find_suitable_scans(application_protocol):

  scans = []
  
  # iterate over each service scan configuration
  for service_name, service_config in SERVICES_CONFIG.items():
    service_patterns = service_config['patterns'] if 'patterns' in service_config else ['.+']

    # iterate over each scan of a specific service config
    for scan_name, scan in service_config['scans'].items():
      scan_command = scan['command']
      scan_patterns = scan['patterns'] if 'patterns' in scan else []

      for service_pattern in service_patterns:
        if re.search(service_pattern, application_protocol):
          scans.append(
            Scan(
              service_name,
              scan_name,
              scan_command,
              scan_patterns,
              True if 'run_once' in scan else False
            )
          )

  return scans

def queue_HTTP_service_scan(target: Target, service: Service, scan: Scan):

  results_directory = pathlib.Path(target.directory, 'services')

  transport_protocol = service.transport_protocol
  port = service.port
  application_protocol = service.application_protocol
  address = target.address

  hostnames = target.hostnames
  if len(hostnames) == 0:
    hostnames.append(address)

  scheme = 'http'
  if application_protocol.startswith('ssl|') or application_protocol.startswith('tls|'):
    scheme = 'https'

  # we have to run the scan for each hostname associated with the target
  for hostname in hostnames:
    result_file = pathlib.Path(results_directory, f"{scan.service}-{port}-{hostname}-{scan.name}.log")
    
    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file.exists() and not OVERWRITE:
      log(f"result file '{result_file}' already exists and we must not overwrite it.")
      continue # with another service of the target

    description = f"{address}: {scan.service}: {port}: {hostname}: {scan.name}"
    log(description)

    scan_ID = (transport_protocol, port, application_protocol, hostname, scan.service, scan.name)

    if scan_ID in target.scans:
      log("[orange]this scan appears to have already been queued")
      continue # with another hostname 
    else:
      target.scans[scan_ID] = Command(
        description,
        format(scan.command),
        scan.patterns
      )

def queue_generic_service_scan(target: Target, service: Service, scan: Scan):

  results_directory = pathlib.Path(target.directory, 'services')

  transport_protocol = service.transport_protocol
  port = service.port
  application_protocol = service.application_protocol
  address = target.address

  # does this service belong to a group that should only be scanned once (e.g. SMB)?
  if scan.run_once:
    result_file = pathlib.Path(results_directory, f'{scan.service}-{scan.name}.log')

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file.exists() and not OVERWRITE:
      log(f"result file '{result_file}' already exists and we must not overwrite it.")
      return # continue with another service of the target

    description = f"{address}: {scan.service}: {scan.name}"
    log(description)

    scan_ID = (scan.service, scan.name)

    if scan_ID in target.scans:
      log("[orange]this scan should only be run once")
      return # continue with another service of the target

  else: # service does not belong to a group that should only be scanned once
    result_file = pathlib.Path(results_directory, f'{scan.service}-{transport_protocol}-{port}-{scan.name}.log')

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file.exists() and not OVERWRITE:
      log(f"result file '{result_file}' already exists and we must not overwrite it.")
      return # continue with another service of the target

    description = f"{address}: {scan.service}: {transport_protocol}/{port}: {scan.name}"
    log(description)

    scan_ID = (transport_protocol, port, application_protocol, scan.service, scan.name)

    if scan_ID in target.scans:
      log("[orange]this scan appears to have already been queued")
      return # continue with another service of the target

  target.scans[scan_ID] = Command(
    description,
    format(scan.command),
    scan.patterns
  )
  
async def scan_services(target: Target):

  # initialize Lock and Semaphore
  # https://stackoverflow.com/a/55918049
  
  # a semaphore is needed to limit the number of concurrent scans per target
  target.semaphore = asyncio.Semaphore(CONCURRENT_SCANS)
  
  # extract the target's address from the object
  # it's referenced like this in the scan configs
  address = target.address

  results_directory = pathlib.Path(target.directory, 'services')
  log(f"results directory: {results_directory}")
  results_directory.mkdir(exist_ok=True)

  # iterate over the services found to be running on the target
  for service in target.services:
    transport_protocol = service.transport_protocol
    port = service.port
    application_protocol = service.application_protocol

    # iterate over each suitable scan
    for scan in find_suitable_scans(application_protocol):
      if scan.service in ('http', 'tls'):
        queue_HTTP_service_scan(target, service, scan)
      else:
        queue_generic_service_scan(target, service, scan)

  tasks = []
  for scan_ID, command in target.scans.items():
    tasks.append(
      asyncio.create_task(
        run_command(command, target)
      )
    )

  for task in tasks:
    await task
  
def scan_target(target: Target):

  # create directory
  target.directory.mkdir(exist_ok=True)

  # sort the target's services based on its port
  target.services.sort(key=lambda service: service.port)

  # create summary to be included in the LaTeX/Markdown report
  create_summary(target)

  # perform service-specific scans
  asyncio.run(scan_services(target))

  progress.console.print(f"[bold green]{target.address}: finished")

def parse_result_file(base_directory, result_file):
  targets = {}

  # a service is uniquely identified by the tuple (host, transport protocol, port number)
  unique_services = []

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
      target = Target(address, pathlib.Path(base_directory, address))
      targets[address] = target
    else:
      target = targets[address]

    try:
      hostname = host.findall("hostnames/hostname[@type='user']")[0].get('name')
      if hostname not in target.hostnames:
        target.hostnames.append(hostname)
    except:
      pass

    log(f"{address} ({','.join(target.hostnames)})")

    for port in host.iter('port'):
      if port.find('state').get('state') != 'open':
        continue

      transport_protocol = port.get('protocol')
      port_ID = port.get('portid')

      service_tuple = (address, transport_protocol, port_ID)
      if service_tuple in unique_services:
        continue

      unique_services.append(service_tuple)

      service = port.find('service')
      if service is None:
        application_protocol = 'unknown'
        description = 'unknown'
      else:
        application_protocol = service.get('name')
        if service.get('tunnel'):
          application_protocol = service.get('tunnel') + '|' + application_protocol

        descriptions = []
        if service.get('product'):
          descriptions.append(service.get('product'))
        if service.get('version'):
          descriptions.append(service.get('version'))
        if service.get('extrainfo'):
          descriptions.append(service.get('extrainfo'))

        description = " ".join(descriptions)

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

  global CONCURRENT_SCANS
  CONCURRENT_SCANS = args.concurrent_scans

  if args.config:
    config_file_path = args.config
    if not config_file_path.exists():
      sys.exit(f"the specified configuration file '{config_file_path}' does not exist!")
  else:
    config_file_path = pathlib.Path(pathlib.Path(__file__).resolve().parent, "config.toml")
    if not config_file_path.exists():
      sys.exit(f"the default configuration file '{config_file_path}' does not exist!")

  global SERVICES_CONFIG
  with open(config_file_path, 'r') as f:
    SERVICES_CONFIG = toml.load(f)

  with progress:
    base_directory = args.output.resolve()
    log(f"base directory: '{base_directory}'")
    base_directory.mkdir(exist_ok=True)

    CommandLog.init(
      pathlib.Path(base_directory, 'commands.csv'),
      asyncio.Lock(),
      ['start time', 'completion time', 'command', 'return code']
    )

    input_file = args.input.resolve()
    if not input_file.exists():
      sys.exit(f"input file '{input_file}' does not exist!")

    # parse Nmap result file of the service scan (XML)
    targets = parse_result_file(base_directory, args.input)
    log(f"parsed {len(targets)} targets")

    with ThreadPoolExecutor(max_workers=args.concurrent_targets) as executor:
      futures = []
      for address, target in targets.items():
        futures.append(executor.submit(scan_target, target))

      try:
        for future in as_completed(futures):
          future.result()
        progress.console.print("[bold green]done")
      except KeyboardInterrupt:
        progress.console.print("[bold red]aborted by user")
        stop_exucutor(executor)

def main():
  parser = argparse.ArgumentParser()

  parser.add_argument('-i', '--input', type=pathlib.Path, default='services.xml', help="the result file of the Nmap service scan (default: 'services.xml')")
  parser.add_argument('-o', '--output', type=pathlib.Path, default='./recon', help="where the results are stored (default: './recon')")
  parser.add_argument('-c', '--config', type=pathlib.Path, help="path to the scan configuration file (default: '/path/to/recon-suite/config.toml')")
  parser.add_argument('-t', '--concurrent_targets', type=int, default=3, help="how many targets should be scanned concurrently (default: 3)")
  parser.add_argument('-s', '--concurrent_scans', type=int, default=2, help="how many scans should be running concurrently on a single target (default: 2)")
  parser.add_argument('-v', '--verbose', action='store_true', help="show additional info including all output of all scans")
  parser.add_argument('-n', '--dry_run', action='store_true', help="do not run any command; just create/update the 'commands.log' file")
  parser.add_argument('-y', '--overwrite_results', action='store_true', help="overwrite existing result files")

  process(parser.parse_args())

if __name__ == '__main__':
  main()
