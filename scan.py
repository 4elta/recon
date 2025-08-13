#!/usr/bin/env python3

# run service-specific scans based on the result of Nmap service scans.

import argparse
import asyncio
import csv
import curses
import datetime
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
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

TITLE = "recon scanner"

PROGRESS_BAR_LENGTH = 10
PROGRESS_BAR_STYLES = {
  'pipe': ['|', '⋅'],
  'pipe2': ['┃', '⋅'],
  'dot': ['●', '⋅'],
}
PROGRESS_BAR_STYLE = 'pipe'

UI = None
TARGETS = {}
STOPPING = False
QUITTING = False

MAIN_PROGRESS_BAR_LENGTH = len("estimated time of completion: yyyy-mm-dd HH:MM") - len(TITLE) - 1

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

class UserInterface:
  '''
  `curses` user interface,
  incl. keyboard event listener
  '''
  def __init__(self, window, screen_width, screen_height):
    self.window = window
    self.window.nodelay(True)

    self.screen_height = screen_height
    self.main = curses.newpad(screen_height + 1, screen_width + 1)
    self.footer = curses.newpad(2, screen_width)

    self.progress_x_pos = None

    self.start_time = datetime.datetime.now()
    self.progress = None

    asyncio.create_task(self.listen_for_keypress())

  async def listen_for_keypress(self):
    global STOPPING, QUITTING

    while True:
      key = self.window.getch()

      if key == -1:
        await asyncio.sleep(0.1)
        continue

      if key == curses.KEY_RESIZE:
        self.update()
        continue

      match chr(key):
        case 'q':
          QUITTING = True
          cancel_tasks()
          break
        case 's':
          STOPPING = True
          self.update()
          break

  def estimate_time_of_completion(self):
    if not self.progress:
      return "estimating time of completion ..."

    now = datetime.datetime.now()
    duration = (now - self.start_time)

    estimated_time_of_completion = self.start_time + duration / self.progress
    return f"estimated time of completion: {estimated_time_of_completion.strftime('%Y-%m-%d %H:%M')}"

  def render_progress(self, partial, total, length=PROGRESS_BAR_LENGTH, style=PROGRESS_BAR_STYLE):
    progress = []
    progress += [PROGRESS_BAR_STYLES[style][0]] * int(partial / total * length)
    progress += [PROGRESS_BAR_STYLES[style][1]] * (length - len(progress))

    return ''.join(progress)

  def update_progress_x_pos(self):
    self.progress_x_pos = 0

    for target_address in TARGETS.keys():
      name_length = len(target_address)
      if name_length > self.progress_x_pos:
        self.progress_x_pos = name_length

    self.progress_x_pos += 1

  def update(self):
    if self.progress_x_pos is None:
      self.update_progress_x_pos()

    self.window.clear()
    self.window.refresh()

    self.main.clear()

    screen_height, screen_width = self.window.getmaxyx()

    line = 2
    number_of_targets_completed = 0
    number_of_scans_total = 0
    number_of_scans_completed_total = 0

    for target in TARGETS.values():
      number_of_scans = len(target.scans)
      number_of_scans_total += number_of_scans

      number_of_scans_completed = target.number_of_scans_completed
      number_of_scans_completed_total += number_of_scans_completed

      if number_of_scans_completed == number_of_scans:
        number_of_targets_completed += 1
        continue

      if not target.active:
        continue

      target_is_active = False
      for scan in target.scans.values():
        if scan.active and not scan.completed:
          target_is_active = True
          break

      if not target_is_active:
        continue

      line += 1

      if line < self.screen_height:
        self.main.addstr(line, 0, f"{target.address}")
        if not STOPPING:
          self.main.addstr(line, self.progress_x_pos, self.render_progress(number_of_scans_completed, number_of_scans))

      line += 1

      for scan in target.scans.values():
        if line >= self.screen_height:
          break

        if not scan.active:
          continue

        self.main.addstr(line, 0, scan.description, curses.A_DIM)
        line += 1

    self.progress = number_of_scans_completed_total / number_of_scans_total

    line = 0
    self.main.addstr(line, 0, TITLE, curses.A_BOLD)
    if STOPPING:
      self.main.addstr(line, len(TITLE) + 1, "... stopping ...", curses.A_BOLD)
      self.main.addstr(line + 1, 0, "waiting for the running scans to finish ...")
    else:
      self.main.addstr(
        line, len(TITLE) + 1,
        self.render_progress(
          number_of_scans_completed_total,
          number_of_scans_total,
          length = MAIN_PROGRESS_BAR_LENGTH,
          style = 'pipe2'
        ),
        curses.A_BOLD
      )
      self.main.addstr(1, 0, self.estimate_time_of_completion())

    self.main.refresh(
      0, 0,
      0, 0,
      screen_height - 1, screen_width - 1
    )

    self.footer.clear()

    if not (STOPPING or QUITTING):
      footer_messages = [
        "[q] quit: kill all running scans",
        "[s] stop gracefully: wait for the currently running scans to finish"
      ]

      for n, msg in enumerate(footer_messages):
        self.footer.addstr(n, 0, msg, curses.A_DIM)

      self.footer.refresh(
        0, 0,
        screen_height - 2, 0,
        screen_height - 1, screen_width - 1
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
    self.semaphore = None # limiting the number of concurrently running scans
    self.address = address
    self.hostnames = []
    self.directory = directory
    self.services = []
    self.scans = {} # dictionary of `Scan`s
    self.active = False
    self.number_of_scans_completed = 0

class ScanDefinition:
  # as parsed from the scanner config (`scanner.toml`)
  def __init__(self, service, name, command, patterns, run_once):
    self.service = service
    self.name = name
    self.command = command
    self.patterns = patterns
    self.run_once = run_once

class Scan:
  def __init__(self, target, host, port, description, command, patterns):
    self.target = target
    self.host = host # address or hostname
    self.port = port
    self.description = description # <host>: <service>: <port>: [<hostname>:] <name>
    self.command = command # the command string
    self.patterns = patterns
    self.active = False
    self.completed = False
    self.return_code = None

  def set_complete(self, return_code):
    self.return_code = return_code
    self.completed = True
    self.active = False
    self.target.number_of_scans_completed += 1

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

  # add global variables from the config
  if 'globals' in CONFIG:
    vals.update(CONFIG['globals'])

  return string.Formatter().vformat(' '.join(args), args, vals)

def create_summary(target: Target):
  
  services_file = pathlib.Path(target.directory.parent, f'{target.address}.md')
  with open(services_file, 'w') as f:
    for service in target.services:
      description = service.application_protocol
      if service.description:
        description = service.description

      f.write(f"* {service.port} ({service.transport_protocol}): `{description}`\n")

async def read_command_results(process, scan):
  # parse STDOUT

  while True:
    line = await process.stdout.readline()
    if line:
      line = str(line.rstrip(), 'utf8', 'ignore')

      for pattern in scan.patterns:
        match = re.search(pattern, line)
        if match:
          info = match.group(0)
          #TODO: do something with the info
    else:
      return

async def run_command(scan: Scan):

  # make sure that only a specific number of scans are running per target
  async with scan.target.semaphore:
    if STOPPING:
      return

    scan.active = True
    UI.update()

    log(f"[{scan.description}]\tstarted")

    timestamp_start = time.time()
    return_code = 0

    if DRY_RUN:
      # add some random delay, just for fun
      await asyncio.sleep(random.randrange(1, 10))
    else:
      # create/start the async process
      process = await asyncio.create_subprocess_shell(
        scan.command,
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE,
        executable = '/bin/bash'
      )

      try:
        # wait for the task (i.e. read command results) to finish within the specified timeout (in seconds)
        # https://docs.python.org/3/library/asyncio-task.html#asyncio.wait_for
        await asyncio.wait_for(read_command_results(process, scan), timeout=MAX_TIME)

        return_code = process.returncode

        if return_code is None:
          return_code = 0

        if return_code not in (0, 'timeout'):
          error_msg = await process.stderr.read()
          error_msg = error_msg.decode().strip()
          log(f"[{scan.description}]\t{error_msg}")
      except asyncio.exceptions.TimeoutError:
        log(f"[{scan.description}]\ttimeout")
        return_code = "timeout"
      except asyncio.exceptions.CancelledError:
        log(f"[{scan.description}]\tcancelled")
        return_code = "cancelled"

    timestamp_completion = time.time()

    await CommandLog.add_entry([timestamp_start, timestamp_completion, scan.host, scan.port, scan.command, return_code])
    
    scan.set_complete(return_code)
    UI.update()

    if return_code not in ('timeout', 'cancelled'):
      log(f"[{scan.description}]\tdone")

def find_suitable_scans(application_protocol):

  scan_definitions = []
  
  # iterate over each service scan configuration
  for service_name, service_config in CONFIG['services'].items():
    service_patterns = service_config['patterns'] if 'patterns' in service_config else ['.+']

    # iterate over each scan of a specific service config
    for scan_name, scan in service_config['scans'].items():
      scan_command = scan['command']
      scan_patterns = scan['patterns'] if 'patterns' in scan else []

      for service_pattern in service_patterns:
        if re.search(service_pattern, application_protocol):
          #log(f"application protocol '{application_protocol}' matched '{service_name}' pattern '{service_pattern}'; command '{scan_name}'")
          scan_definitions.append(
            ScanDefinition(
              service_name,
              scan_name,
              scan_command,
              scan_patterns,
              True if 'run_once' in scan else False
            )
          )

  return scan_definitions

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

def queue_service_scan_hostname(target: Target, service: Service, scan_definition: ScanDefinition):
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
    file_name = f'{scan_definition.service},{transport_protocol},{port},{hostname},{scan_definition.name}'
    result_file = pathlib.Path(results_directory, file_name)

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file_exists(results_directory, file_name):
      continue # with another hostname

    scan_ID = (transport_protocol, port, application_protocol, hostname, scan_definition.service, scan_definition.name)

    if scan_ID in target.scans:
      continue # with another hostname 

    description = f"{address}: {scan_definition.service}: {port}: {hostname}: {scan_definition.name}"

    log(f"[{description}]")

    target.scans[scan_ID] = Scan(
      target,
      hostname,
      port,
      description,
      format(scan_definition.command),
      scan_definition.patterns
    )

def queue_service_scan_address(target: Target, service: Service, scan_definition: ScanDefinition):
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
  if scan_definition.run_once:
    file_name = f'{scan_definition.service},{scan_definition.name}'
    result_file = pathlib.Path(results_directory, file_name)

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file_exists(results_directory, file_name):
      return # continue with another service of the target

    description = f"{address}: {scan_definition.service}: {scan_definition.name}"

    scan_ID = (scan_definition.service, scan_definition.name)

    if scan_ID in target.scans:
      return # continue with another service of the target

  else: # service does not belong to a group that should only be scanned once
    file_name = f'{scan_definition.service},{transport_protocol},{port},{scan_definition.name}'
    result_file = pathlib.Path(results_directory, file_name)

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file_exists(results_directory, file_name):
      return # continue with another service of the target

    description = f"{address}: {scan_definition.service}: {transport_protocol}/{port}: {scan_definition.name}"

    scan_ID = (transport_protocol, port, application_protocol, scan_definition.service, scan_definition.name)

    if scan_ID in target.scans:
      return # continue with another service of the target

  log(f"[{description}]")

  target.scans[scan_ID] = Scan(
    target,
    address,
    port,
    description,
    format(scan_definition.command),
    scan_definition.patterns
  )
  
async def scan_services(target: Target):

  # extract the target's address from the object.
  # it's referenced like this (i.e. `{address}`) in the scan configs.
  address = target.address

  log(f"[{address}]\tstarted")

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
    for scan_definition in suitable_scans:
      if scan_definition.service in ('http', 'tls'):
        queue_service_scan_hostname(target, service, scan_definition)
      else:
        queue_service_scan_address(target, service, scan_definition)

  tasks = set()
  for scan in target.scans.values():
    if STOPPING:
      break

    tasks.add(
      asyncio.create_task(
        run_command(scan)
      )
    )

  await asyncio.gather(*tasks)

  log(f"[{address}]\tdone")
  
async def scan_target(semaphore: asyncio.Semaphore, target: Target):
  
  target.directory.mkdir(exist_ok=True)

  # sort the target's services based on its port
  target.services.sort(key=lambda service: service.port)

  create_summary(target)

  # make sure that only a specific number of targets are scanned in parallel
  async with semaphore:
    if STOPPING:
      return

    target.active = True

    log(f"[{target.address}]")

    await scan_services(target)

    log(f"[{target.address}]\tdone")

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

def load_config(config_files):
  config = None

  # default configuration file
  config_file_path = pathlib.Path(
    pathlib.Path(__file__).resolve().parent,
    "config",
    "scanner.toml"
  )

  log(f"loading default configuration file '{config_file_path}' ...")

  if not config_file_path.exists():
    log("the file does not exist")
    sys.exit("the default configuration file does not exist!")

  with open(config_file_path, 'rb') as f:
    config = toml.load(f)

  if not config_files:
    return config

  # user-specified configuration files
  for config_file_path in config_files:
    log(f"loading config '{config_file_path}'")

    if not config_file_path.exists():
      log(f"the specified configuration file does not exist")
      continue

    with open(config_file_path, 'rb') as f:
      new_config = toml.load(f)

    if 'merge_strategy' in new_config and new_config['merge_strategy'] == 'overwrite':
      # overwrite config
      log("overriding config ...")
      config = new_config
    else:
      log("merging config ...")
      # https://peps.python.org/pep-0584/

      if 'globals' in new_config:
        config['globals'] |= new_config['globals']

      if 'services' in new_config:
        for service_name, service_config in new_config['services'].items():
          if service_name not in config['services']:
            config['services'][service_name] = service_config
            continue

          if 'patterns' in service_config:
            config['services'][service_name]['patterns']= service_config['patterns']

          if 'scans' not in service_config:
            continue

          for scan_name, scan_config in service_config['scans'].items():
            if scan_name not in config['services'][service_name]['scans']:
              config['services'][service_name]['scans'][scan_name] = scan_config
              continue

            if 'patterns' in scan_config:
              config['services'][service_name]['scans'][scan_name]['patterns'] = scan_config['patterns']

            if 'command' in scan_config:
              config['services'][service_name]['scans'][scan_name]['command'] = scan_config['command']

            if 'run_once' in scan_config:
              config['services'][service_name]['scans'][scan_name]['run_once'] = scan_config['run_once']

  return config

async def process(stdscr, args):
  loop = asyncio.get_running_loop()

  for signame in ('SIGINT', 'SIGTERM'):
    loop.add_signal_handler(
      getattr(signal, signame),
      cancel_tasks
    )

  # hide cursor
  curses.curs_set(0)

  # necessary, otherwise the colors are inverted when running the scanner via SSH
  curses.use_default_colors()

  global DRY_RUN
  DRY_RUN = args.dry_run

  global OVERWRITE
  OVERWRITE = args.overwrite_results

  global MAX_TIME
  MAX_TIME = args.max_time

  if not os.geteuid() == 0 and not args.ignore_uid:
    sys.exit('depending on what commands/tools this script executes it might have to be run by the root user (i.e. with "sudo").\nyou could try and ignore this warning by using the `--ignore-uid` flag.')

  # limit the number of concurrently scanned targets
  concurrent_targets = asyncio.Semaphore(args.concurrent_targets)

  base_directory = args.output.resolve()
  base_directory.mkdir(exist_ok=True)

  timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

  global LOG_FILE
  LOG_FILE = pathlib.Path(
    base_directory,
    f'scanner_{timestamp}.log'
  )

  log(f"base directory: '{base_directory}'")

  global CONFIG
  CONFIG = load_config(args.config)

  config_file = pathlib.Path(
    base_directory,
    f'config_{timestamp}.json'
  )

  with open(config_file, 'w') as f:
    json.dump(CONFIG, f, indent=4)

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

  global TARGETS
  TARGETS = parse_result_files(base_directory, args.input, rescan_filters)
  log(f"parsed {len(TARGETS)} targets")

  # create services.csv file and initialize its header
  with open(pathlib.Path(base_directory, 'services.csv'), 'w') as f:
    csv.writer(f, delimiter=args.delimiter, quoting=csv.QUOTE_MINIMAL).writerow(['host', 'transport_protocol', 'port', 'service', 'scanned'])

  global UI
  UI = UserInterface(stdscr, 80, args.concurrent_targets * (args.concurrent_scans + 2) + 4)

  # each target in its own task ...
  tasks = set()
  for target in TARGETS.values():
    # limit the number of concurrent scans per target
    target.semaphore = asyncio.Semaphore(args.concurrent_scans)

    tasks.add(
      asyncio.create_task(
        scan_target(
          concurrent_targets,
          target
        )
      )
    )

  await asyncio.gather(*tasks)

  # fill services.csv file with the found services services
  with open(pathlib.Path(base_directory, 'services.csv'), 'a') as f:
    for address, target in TARGETS.items():
      for service in target.services:
        row = [address, service.transport_protocol, service.port, service.application_protocol, service.scanned]
        csv.writer(f, delimiter=args.delimiter, quoting=csv.QUOTE_MINIMAL).writerow(row)

def cancel_tasks():
  global QUITTING
  QUITTING = True

  log("aborted by user")

  asyncio.get_running_loop().stop()

def main():
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
    help = "path to the scanner configuration file(s); see '/path/to/recon/config/scanner.toml'",
    type = pathlib.Path,
    nargs = '+'
  )

  parser.add_argument(
    '-t', '--concurrent-targets',
    metavar = 'number',
    help = "number of targets that should be scanned concurrently (default: 3)",
    type = int,
    default = 3
  )

  parser.add_argument(
    '-s', '--concurrent-scans',
    metavar = 'number',
    help = "number of scans that should be running concurrently on a single target (default: 2)",
    type = int,
    default = 2
  )

  parser.add_argument(
    '-m', '--max-time',
    metavar = 'seconds',
    help = f"maximum time in seconds each scan is allowed to take (default: {MAX_TIME})",
    type = int,
    default = MAX_TIME
  )

  parser.add_argument(
    '-n', '--dry-run',
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
    '-y', '--overwrite-results',
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
    '--ignore-uid',
    help = "ignore the warning about potentially lacking permissions",
    action = 'store_true'
  )

  args = parser.parse_args()

  try:
    curses.wrapper(lambda stdscr: asyncio.run(process(stdscr, args)))
  except RuntimeError:
    pass

if __name__ == '__main__':
  start_time = datetime.datetime.now()

  main()

  end_time = datetime.datetime.now()

  unsuccessful_scans = []
  number_of_scans = 0
  number_of_completed_scans = 0
  number_of_scanned_targets = 0
  for target in TARGETS.values():
    number_of_scans += len(target.scans)
    if target.number_of_scans_completed:
      number_of_scanned_targets += 1
      number_of_completed_scans += target.number_of_scans_completed

    for scan in target.scans.values():
      if scan.completed and scan.return_code != 0:
        unsuccessful_scans.append(scan.command)

  if QUITTING:
    print("user aborted: some scans might have been killed before they were finished.")

  print(f"recon scanner ran {end_time - start_time} (hours:minutes:seconds).")
  print(f"{number_of_scanned_targets} of {len(TARGETS)} targets were scanned ({100 * number_of_scanned_targets / len(TARGETS):.1f} %).")
  print(f"{number_of_completed_scans} of {number_of_scans} scans completed ({100 * number_of_completed_scans / number_of_scans:.1f} %).")
  if len(unsuccessful_scans):
    print(f"{len(unsuccessful_scans)} of those scans returned an error, ran into a timeout or were cancelled.")
