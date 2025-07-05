#!/usr/bin/env python3

# run service-specific scans based on the result of Nmap service scans.

import argparse
import asyncio
import csv
import functools
import inspect
import json
import os
import pathlib
import random
import re
import signal
import string
import subprocess
import sys
import time
import tomllib as toml

try:
  # https://rich.readthedocs.io/en/latest/index.html
  import rich
except:
  sys.exit("this script requires the 'rich' module.\nplease install it via 'pip3 install rich'.")

from rich.console import Group
from rich.live import Live
from rich.progress import Progress, SpinnerColumn

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

OVERALL_PROGRESS = Progress(
  SpinnerColumn(),
  "[progress.description]{task.description}",
  "{task.completed}/{task.total}",
  transient = True,
)
OVERALL_TASK = None

JOB_PROGRESS = Progress(
  SpinnerColumn(),
  "[progress.description]{task.description}",
  transient = True,
)

# error/debug log
LOG_FILE = None

# <host>:<protocol>:<port>:<service>
RESCAN_PATTERN = re.compile(r'(?P<host>[^:]+):(?P<protocol>(tcp|udp|\*)):(?P<port>(\d+)|\*):(?P<service>.+)')

# default timeout (in seconds) after which a command will be cancelled
MAX_TIME = 60*60

PATH_TO_SCANNERS = pathlib.Path(
  pathlib.Path(__file__).resolve().parent,
  "scanners"
)

class Service:
  def __init__(self, transport_protocol, port, application_protocol, description):
    self.transport_protocol = transport_protocol
    self.port = int(port)
    self.application_protocol = application_protocol
    self.description = description
    self.scanned = False

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
  def __init__(self, host, port, description, string, patterns):
    self.host = host
    self.port = port
    self.description = description
    self.string = string
    self.patterns = patterns

class CommandLog:

  path = None
  lock = None # ensures that only a single thread can write to the commands log
  delimiter = ','

  @classmethod
  def init(cls, path, lock, header, delimiter):
    cls.path = path
    cls.lock = lock
    cls.delimiter = delimiter

    if not path.exists(): # do not overwrite the log
      with open(cls.path, 'w') as f:
        csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(header)

  @classmethod
  async def add_entry(cls, entry):
    async with cls.lock:
      with open(cls.path, 'a') as f:
        csv.writer(f, delimiter=cls.delimiter, quoting=csv.QUOTE_MINIMAL).writerow(entry)

def log(msg):
  if not LOG_FILE:
    return

  with open(LOG_FILE, 'a') as f:
    current_task = asyncio.current_task()

    if current_task:
      task_name = current_task.get_name()
    else:
      task_name = 'main'

    method_name = inspect.stack()[1].function
    f.write(f"[{task_name}]\t[{method_name}]\t{msg}\n")

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

  # add the variables from the general service group
  if '*' in SERVICES_CONFIG:
    vals.update(SERVICES_CONFIG['*'])

  return string.Formatter().vformat(' '.join(args), args, vals)

def create_summary(target: Target):
  
  services_file = pathlib.Path(target.directory.parent, f'{target.address}.md')
  with open(services_file, 'w') as f:
    for service in target.services:
      description = service.application_protocol
      if service.description:
        description = service.description

      f.write(f"* {service.port} ({service.transport_protocol}): `{description}`\n")

async def read_command_results(process, command):
  # parse STDOUT

  while True:
    line = await process.stdout.readline()
    if line:
      line = str(line.rstrip(), 'utf8', 'ignore')

      for pattern in command.patterns:
        match = re.search(pattern, line)
        if match:
          JOB_PROGRESS.console.print(f"{command.description}: \"{match.group(0)}\"")
    else:
      return

async def run_command(command: Command, target: Target):

  # make sure that only a specific number of scans are running per target
  async with target.semaphore:
    log(f"[{command.description}]")
    task_ID = JOB_PROGRESS.add_task(f"{command.description}")

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

      try:
        # wait for the task (i.e. read command results) to finish within the specified timeout (in seconds)
        # https://docs.python.org/3/library/asyncio-task.html#asyncio.wait_for
        await asyncio.wait_for(read_command_results(process, command), timeout=MAX_TIME)

        return_code = process.returncode

        if return_code is None:
          return_code = 0

        if return_code not in (0, 'timeout'):
          error_msg = await process.stderr.read()
          error_msg = error_msg.decode().strip()
          OVERALL_PROGRESS.console.print(f"[red]{command.description}: {error_msg}")
          log(f"[{command.description}]\t{error_msg}")
      except asyncio.exceptions.TimeoutError:
        OVERALL_PROGRESS.console.print(f"[red]{command.description}: timeout")
        log(f"[{command.description}]\ttimeout")
        return_code = "timeout"
      except asyncio.exceptions.CancelledError:
        log(f"[{command.description}]\tcancelled")
        return_code = "cancelled"

    timestamp_completion = time.time()

    await CommandLog.add_entry([timestamp_start, timestamp_completion, command.host, command.port, command.string, return_code])
    
    JOB_PROGRESS.remove_task(task_ID)

    if return_code not in ('timeout', 'cancelled'):
      log(f"[{command.description}]\tdone")

def find_suitable_scans(application_protocol):

  scans = []
  
  # iterate over each service scan configuration
  for service_name, service_config in SERVICES_CONFIG.items():
    if service_name == '*': # ignore the general service group
      continue

    service_patterns = service_config['patterns'] if 'patterns' in service_config else ['.+']

    # iterate over each scan of a specific service config
    for scan_name, scan in service_config['scans'].items():
      scan_command = scan['command']
      scan_patterns = scan['patterns'] if 'patterns' in scan else []

      for service_pattern in service_patterns:
        if re.search(service_pattern, application_protocol):
          #log(f"application protocol '{application_protocol}' matched '{service_name}' pattern '{service_pattern}'; command '{scan_name}'")
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

def result_file_exists(results_directory, file_name):
  result_files = 0
  for result_file in results_directory.glob(f'{file_name}.*'):
    if OVERWRITE:
      result_file.unlink()
    else:
      result_files += 1

  if result_files > 0 and not OVERWRITE:
    log(f"'{results_directory}/{file_name}.*' exists and we must not overwrite them.")
    return True

def queue_service_scan_hostname(target: Target, service: Service, scan: Scan):
  '''
  queue a scan of a service that recognizes the concept of a hostname in contrast/addition to an IP address (e.g. HTTP, TLS)
  '''

  results_directory = target.directory

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

  application_protocol = 'http'

  # we have to run the scan for each hostname associated with the target
  for hostname in hostnames:
    file_name = f'{scan.service},{transport_protocol},{port},{hostname},{scan.name}'
    result_file = pathlib.Path(results_directory, file_name)

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file_exists(results_directory, file_name):
      continue # with another hostname

    scan_ID = (transport_protocol, port, application_protocol, hostname, scan.service, scan.name)

    if scan_ID in target.scans:
      continue # with another hostname 

    description = f"{address}: {scan.service}: {port}: {hostname}: {scan.name}"

    log(f"[{description}]")

    target.scans[scan_ID] = Command(
      hostname,
      port,
      description,
      format(scan.command),
      scan.patterns
    )

def queue_service_scan_address(target: Target, service: Service, scan: Scan):
  '''
  queue a scan of a service that does not recognize the concept of a hostname
  '''

  results_directory = target.directory

  transport_protocol = service.transport_protocol
  port = service.port
  application_protocol = service.application_protocol
  address = target.address

  if '|' in application_protocol:
    # e.g. "ssl|smtp" or "tls|smtp"
    _, application_protocol = application_protocol.split('|')

  # does this service belong to a group that should only be scanned once (e.g. SMB)?
  if scan.run_once:
    file_name = f'{scan.service},{scan.name}'
    result_file = pathlib.Path(results_directory, file_name)

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file_exists(results_directory, file_name):
      return # continue with another service of the target

    description = f"{address}: {scan.service}: {scan.name}"

    scan_ID = (scan.service, scan.name)

    if scan_ID in target.scans:
      return # continue with another service of the target

  else: # service does not belong to a group that should only be scanned once
    file_name = f'{scan.service},{transport_protocol},{port},{scan.name}'
    result_file = pathlib.Path(results_directory, file_name)

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file_exists(results_directory, file_name):
      return # continue with another service of the target

    description = f"{address}: {scan.service}: {transport_protocol}/{port}: {scan.name}"

    scan_ID = (transport_protocol, port, application_protocol, scan.service, scan.name)

    if scan_ID in target.scans:
      return # continue with another service of the target

  log(f"[{description}]")

  target.scans[scan_ID] = Command(
    address,
    port,
    description,
    format(scan.command),
    scan.patterns
  )
  
async def scan_services(target: Target):

  # extract the target's address from the object.
  # it's referenced like this (i.e. `{address}`) in the scan configs.
  address = target.address

  log(f"[{address}]")

  # iterate over the services found to be running on the target
  for service in target.services:
    transport_protocol = service.transport_protocol
    port = service.port
    application_protocol = service.application_protocol

    # find suitable scans based on the service's application protocol
    suitable_scans = find_suitable_scans(application_protocol)

    # mark the service as "scanned" if at least 1 suitable scan was found; even though there is not even a scan scheduled yet
    service.scanned = (len(suitable_scans) > 0)

    # iterate over each suitable scan
    for scan in suitable_scans:
      if scan.service in ('http', 'tls'):
        queue_service_scan_hostname(target, service, scan)
      else:
        queue_service_scan_address(target, service, scan)

  tasks = []
  for scan_ID, command in target.scans.items():
    tasks.append(
      asyncio.create_task(
        run_command(command, target)
      )
    )

  for task in tasks:
    await task

  log(f"[{address}]\tdone")
  
async def scan_target(target: Target, semaphore: asyncio.Semaphore):
  
  target.directory.mkdir(exist_ok=True)

  # sort the target's services based on its port
  target.services.sort(key=lambda service: service.port)

  create_summary(target)

  # make sure that only a specific number of targets are scanned in parallel
  async with semaphore:

    log(f"[{target.address}]")
    await scan_services(target)

    JOB_PROGRESS.console.print(f"[bold green]{target.address}: finished")
    log(f"[{target.address}]\tdone")

    OVERALL_PROGRESS.update(OVERALL_TASK, advance=1)

def parse_result_file(base_directory, result_file, targets, unique_services, rescan_filters):
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
      hostname = host.find("./hostnames/hostname[@type='user']").get('name')
      if hostname not in target.hostnames:
        target.hostnames.append(hostname)
    except:
      pass

    log(f"{address} ({','.join(target.hostnames)})")

    for port in host.findall('./ports/port/state[@state="open"]/..'):
      transport_protocol = port.get('protocol')
      port_ID = port.get('portid')

      service_tuple = (address, transport_protocol, port_ID)

      if service_tuple in unique_services:
        continue

      log(f"service {service_tuple}")
      unique_services.append(service_tuple)

      service = port.find('service')
      if service is None:
        application_protocol = 'unknown'
        description = 'unknown'
      else:
        application_protocol = service.get('name')

        # sometimes, Nmap identifies HTTPS as `name="http" ... tunnel="ssl"` instead of `name="https"`.
        # we prepend the tunnel info to the application protocol:
        # '<tunnel>|<application protocol>'
        if service.get('tunnel'):
          log(f"application protocol '{application_protocol}' is tunneled through '{service.get('tunnel')}'")
          application_protocol = service.get('tunnel') + '|' + application_protocol

        descriptions = []
        if service.get('product'):
          descriptions.append(service.get('product'))
        if service.get('version'):
          descriptions.append(service.get('version'))
        if service.get('extrainfo'):
          descriptions.append(service.get('extrainfo'))

        description = " ".join(descriptions)

      add_target = (len(rescan_filters) == 0)
      for rescan_filter in rescan_filters:
        if not (rescan_filter['host'] == '*' or rescan_filter['host'] == address):
          continue

        if not (rescan_filter['protocol'] == '*' or rescan_filter['protocol'] == transport_protocol):
          continue

        if not (rescan_filter['port'] == '*' or rescan_filter['port'] == port_ID):
          continue

        if not (rescan_filter['service'] == '*' or rescan_filter['service'] == application_protocol):
          continue

        log(f"rescan filter '{json.dumps(rescan_filter)}' matches!")
        add_target = True
        break

      if add_target:
        target.services.append(
          Service(
            transport_protocol,
            port_ID,
            application_protocol,
            description
          )
        )

        log(f"{transport_protocol}/{port_ID}: {application_protocol}: {description}")

  return targets

def parse_result_files(base_directory, result_files, rescan_filters):
  targets = {}

  # a service is uniquely identified by the tuple (host, transport protocol, port number)
  unique_services = []

  for result_file in result_files:
    log(f"parsing '{result_file}' ...")
    parse_result_file(base_directory, result_file, targets, unique_services, rescan_filters)

  return targets

async def process(args):
  global DRY_RUN
  DRY_RUN = args.dry_run

  global OVERWRITE
  OVERWRITE = args.overwrite_results

  global MAX_TIME
  MAX_TIME = args.max_time

  if not os.geteuid() == 0 and not args.ignore_uid:
    sys.exit('depending on what commands/tools this script executes it might have to be run by the root user (i.e. with "sudo").\nyou could try and ignore this warning by using the `--ignore_uid` flag.')

  # limit the number of concurrently scanned targets
  concurrent_targets = asyncio.Semaphore(args.concurrent_targets)

  if args.config:
    config_file_path = args.config
    if not config_file_path.exists():
      sys.exit(f"the specified configuration file '{config_file_path}' does not exist!")
  else:
    config_file_path = pathlib.Path(
      pathlib.Path(__file__).resolve().parent,
      "config",
      "scanner.toml"
    )
    if not config_file_path.exists():
      sys.exit(f"the default configuration file '{config_file_path}' does not exist!")

  global SERVICES_CONFIG
  with open(config_file_path, 'rb') as f:
    SERVICES_CONFIG = toml.load(f)

  base_directory = args.output.resolve()
  base_directory.mkdir(exist_ok=True)

  global LOG_FILE
  LOG_FILE = pathlib.Path(base_directory, 'scan.log')

  log(f"base directory: '{base_directory}'")

  CommandLog.init(
    pathlib.Path(base_directory, 'commands.csv'),
    asyncio.Lock(),
    ['start time', 'completion time', 'host', 'port', 'command', 'return code'],
    args.delimiter
  )

  for input_path in args.input:
    input_file = input_path.resolve()
    if not input_file.exists():
      sys.exit(f"input file '{input_file}' does not exist!")

  rescan_filters = []
  for rescan in args.rescan:
    m = RESCAN_PATTERN.fullmatch(rescan)
    if not m:
      sys.exit(f"rescan filter '{rescan}' does not match '{RESCAN_PATTERN.pattern}'")

    rescan_filter = {
      'host': m.group('host'),
      'protocol': m.group('protocol'),
      'port': m.group('port'),
      'service': m.group('service')
    }

    log(f"parsed rescan filter: {json.dumps(rescan_filter)}")
    rescan_filters.append(rescan_filter)

  if len(rescan_filters):
    OVERWRITE = True

  # parse Nmap result file(s), i.e. service.xml
  targets = parse_result_files(base_directory, args.input, rescan_filters)
  log(f"parsed {len(targets)} targets")

  # create services.csv file and initialize its header
  with open(pathlib.Path(base_directory, 'services.csv'), 'w') as f:
    csv.writer(f, delimiter=args.delimiter, quoting=csv.QUOTE_MINIMAL).writerow(['host', 'transport_protocol', 'port', 'service', 'scanned'])

  global OVERALL_TASK
  OVERALL_TASK = OVERALL_PROGRESS.add_task("overall progress:", total=len(targets))

  group = Group(
    JOB_PROGRESS,
    OVERALL_PROGRESS,
  )

  with Live(group):
    # each target in its own task ...
    tasks = []
    for address, target in targets.items():
      # limit the number of concurrent scans per target
      target.semaphore = asyncio.Semaphore(args.concurrent_scans)

      tasks.append(
        asyncio.create_task(
          scan_target(target, concurrent_targets)
        )
      )

    for task in tasks:
      await task

    OVERALL_PROGRESS.remove_task(OVERALL_TASK)

  # fill services.csv file with the found services services
  with open(pathlib.Path(base_directory, 'services.csv'), 'a') as f:
    for address, target in targets.items():
      for service in target.services:
        row = [address, service.transport_protocol, service.port, service.application_protocol, service.scanned]
        csv.writer(f, delimiter=args.delimiter, quoting=csv.QUOTE_MINIMAL).writerow(row)

def cancel_tasks(loop):
  print("aborted by user")
  log("aborted by user")

  loop.stop()

async def main():
  parser = argparse.ArgumentParser(
    description = "Schedule and execute various tools based on the findings of an Nmap service scan."
  )

  parser.add_argument(
    '-i', '--input',
    metavar = 'path',
    help = "path to the result file(s) of the Nmap service scan (default: 'services.xml')",
    type = pathlib.Path,
    nargs = '+',
    default = 'services.xml'
  )

  parser.add_argument(
    '-o', '--output',
    metavar = 'path',
    help = "path to where the results are stored (default: './recon')",
    type = pathlib.Path,
    default = './recon'
  )

  parser.add_argument(
    '-c', '--config',
    metavar = 'path',
    help = "path to the scanner configuration file (default: '/path/to/recon/config/scanner.toml')",
    type = pathlib.Path
  )

  parser.add_argument(
    '-t', '--concurrent_targets',
    metavar = 'number',
    help = "number of targets that should be scanned concurrently (default: 3)",
    type = int,
    default = 3
  )

  parser.add_argument(
    '-s', '--concurrent_scans',
    metavar = 'number',
    help = "number of scans that should be running concurrently on a single target (default: 2)",
    type = int,
    default = 2
  )

  parser.add_argument(
    '-m', '--max_time',
    metavar = 'seconds',
    help = f"maximum time in seconds each scan is allowed to take (default: {MAX_TIME})",
    type = int,
    default = MAX_TIME
  )

  parser.add_argument(
    '-n', '--dry_run',
    help = "do not run any command; just create/update the 'commands.csv' file",
    action = 'store_true'
  )

  parser.add_argument(
    '-r', '--rescan',
    metavar = '<host>:<protocol>:<port>:<service>',
    help = "re-scan certain hosts/protocols/ports/services and overwrite existing result files;\nyou can use '*' if you cannot or don't want to specify a host/protocol/port/service part",
    nargs = '+',
    default = []
  )

  parser.add_argument(
    '-y', '--overwrite_results',
    help = "overwrite existing result files",
    action = 'store_true'
  )

  parser.add_argument(
    '-d', '--delimiter',
    metavar = 'character',
    help = "character used to delimit columns in the 'commands.csv' and 'services.csv' files (default: ',')",
    default = ','
  )

  parser.add_argument(
    '--ignore_uid',
    help = "ignore the warning about potentially lacking permissions",
    action = 'store_true'
  )

  loop = asyncio.get_running_loop()

  for signame in ('SIGINT', 'SIGTERM'):
    loop.add_signal_handler(
      getattr(signal, signame),
      functools.partial(cancel_tasks, loop)
    )

  await process(parser.parse_args())

if __name__ == '__main__':
  try:
    asyncio.run(main())
  except RuntimeError:
    pass
