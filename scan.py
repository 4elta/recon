#!/usr/bin/env python3

# run service-specific scans based on the result of Nmap service scans.

import argparse
import asyncio
import csv
import curses
import datetime
import functools
import inspect
import ipaddress
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

FOOTER_MESSAGES = [
  "[q] quit: kill all running scans",
  "[s] stop gracefully: wait for the currently running scans to finish"
]

# error/debug log
LOG_FILE = None

# default timeout (in seconds) after which a command will be cancelled
MAX_TIME = 60*60

PATH_TO_SCANNERS = pathlib.Path(
  pathlib.Path(__file__).resolve().parent,
  "scanners"
)

PATH_TO_DEFAULT_CONFIG_FILE = pathlib.Path(
  pathlib.Path(__file__).resolve().parent,
  "config",
  "scanner.toml"
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
    self.header = curses.newpad(4, screen_width)
    self.main = curses.newpad(screen_height + 1, screen_width + 1)
    self.footer = curses.newpad(len(FOOTER_MESSAGES), screen_width)

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

    screen_height, screen_width = self.window.getmaxyx()

    self.main.clear()

    line = 0
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

        scan_description = ': '.join(scan.description[1:])
        self.main.addstr(line, 0, scan_description)
        line += 1

      line += 1

    self.main.refresh(
      0, 0,
      4, 0,
      screen_height - 1, screen_width - 1
    )

    self.progress = number_of_scans_completed_total / number_of_scans_total

    self.header.clear()

    self.header.addstr(0, 0, TITLE, curses.A_BOLD)
    self.header.addstr(1, 0, f"running {number_of_scans_total} scans, targeting {len(TARGETS)} hosts")
    if STOPPING:
      self.header.addstr(0, len(TITLE) + 1, "... stopping ...", curses.A_BOLD)
      self.header.addstr(2, 0, "waiting for the running scans to finish ...")
    else:
      self.header.addstr(
        0, len(TITLE) + 1,
        self.render_progress(
          number_of_scans_completed_total,
          number_of_scans_total,
          length = MAIN_PROGRESS_BAR_LENGTH,
          style = 'pipe2'
        )
      )
      self.header.addstr(2, 0, self.estimate_time_of_completion())

    self.header.refresh(
      0, 0,
      0, 0,
      screen_height - 1, screen_width - 1
    )

    self.footer.clear()

    if not (STOPPING or QUITTING):
      for n, msg in enumerate(FOOTER_MESSAGES):
        self.footer.addstr(n, 0, msg, curses.A_DIM)

      self.footer.refresh(
        0, 0,
        screen_height - len(FOOTER_MESSAGES), 0,
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
  def __init__(self, service, name, command, run_once):
    self.service = service
    self.name = name
    self.command = command
    self.run_once = run_once

class Scan:
  def __init__(self, target, host, port, description, command):
    self.target = target
    self.host = host # address or hostname
    self.port = port
    self.description = description # [<host>, <transport protocol>/<port>, <service>, <hostname>, <name>]
    self.command = command # the command string
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

def freeze_variables(*args, frame_index=1, **kvargs):
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

async def run_command(scan: Scan):

  # make sure that only a specific number of scans are running per target
  async with scan.target.semaphore:
    if STOPPING:
      return

    scan.active = True
    UI.update()

    scan_description = ': '.join(scan.description)
    log(f"[{scan_description}]\tstarted")

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
        # wait for the process to finish within the specified timeout (in seconds)
        # https://docs.python.org/3/library/asyncio-task.html#asyncio.wait_for
        await asyncio.wait_for(process.wait(), timeout=MAX_TIME)

        return_code = process.returncode

        if return_code is None:
          return_code = 0

        if return_code not in (0, 'timeout'):
          error_msg = await process.stderr.read()
          error_msg = error_msg.decode().strip()
          log(f"[{scan_description}]\t{error_msg}")
      except asyncio.exceptions.TimeoutError:
        log(f"[{scan_description}]\ttimeout")
        process.terminate()
        return_code = "timeout"
      except asyncio.exceptions.CancelledError:
        log(f"[{scan_description}]\tcancelled")
        return_code = "cancelled"

    timestamp_completion = time.time()

    await CommandLog.add_entry([timestamp_start, timestamp_completion, scan.host, scan.port, scan.command, return_code])
    
    scan.set_complete(return_code)
    UI.update()

    if return_code not in ('timeout', 'cancelled'):
      log(f"[{scan_description}]\tdone")

def find_suitable_scans(transport_protocol, application_protocol):

  scan_definitions = []
  
  # iterate over each service config
  for service_config in CONFIG['services']:
    service_name = service_config['name']

    if 'transport_protocol' in service_config:
      if not re.search(service_config['transport_protocol'], transport_protocol):
        continue

    if 'application_protocol' in service_config:
      if not re.search(service_config['application_protocol'], application_protocol):
        continue

    # iterate over each scan of a specific service config
    for scan_config in service_config['scans']:
      scan_name = scan_config['name']

      if 'transport_protocol' in scan_config:
        if not re.search(scan_config['transport_protocol'], transport_protocol):
          continue

      if 'application_protocol' in scan_config:
        if not re.search(scan_config['application_protocol'], application_protocol):
          continue

      log(f"suitable scan for '{transport_protocol}/{application_protocol}' found: '{service_name}:{scan_name}'")

      scan_definitions.append(
        ScanDefinition(
          service_name,
          scan_name,
          scan_config['command'],
          scan_config['run_once'] if 'run_once' in scan_config else False
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

def get_address_type(address):
  try:
    ip_address = ipaddress.ip_address(address)
    match ip_address.version:
      case 4:
        return 'IPv4'
      case 6:
        return 'IPv6'
  except ValueError:
    return 'hostname'

def queue_service_scan_hostname(target: Target, service: Service, scan_definition: ScanDefinition):
  '''
  queue a scan of a service that recognizes the concept of a hostname in contrast/addition to an IP address (e.g. HTTP, TLS)
  '''

  results_directory = target.directory

  # these variables are required for the scan command (i.e. `freeze_variables`)
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

    description = [
      address,
      f"{transport_protocol}/{port}",
      scan_definition.service,
      hostname,
      scan_definition.name
    ]

    log(f"[{': '.join(description)}]")

    address_type = get_address_type(hostname)

    target.scans[scan_ID] = Scan(
      target,
      hostname,
      port,
      description,
      freeze_variables(scan_definition.command)
    )

def queue_service_scan_address(target: Target, service: Service, scan_definition: ScanDefinition):
  '''
  queue a scan of a service that does not recognize the concept of a hostname
  '''

  results_directory = target.directory

  # these variables are required for the scan command (i.e. `freeze_variables`)
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

    description = [
      address,
      scan_definition.service,
      scan_definition.name
    ]

    scan_ID = (scan_definition.service, scan_definition.name)

    if scan_ID in target.scans:
      return # continue with another service of the target

  else: # service does not belong to a group that should only be scanned once
    file_name = f'{scan_definition.service},{transport_protocol},{port},{scan_definition.name}'
    result_file = pathlib.Path(results_directory, file_name)

    # run scan only if result file does not yet exist or "overwrite_results" flag is set
    if result_file_exists(results_directory, file_name):
      return # continue with another service of the target

    description = [
      address,
      f"{transport_protocol}/{port}",
      scan_definition.service,
      scan_definition.name
    ]

    scan_ID = (transport_protocol, port, application_protocol, scan_definition.service, scan_definition.name)

    if scan_ID in target.scans:
      return # continue with another service of the target

  log(f"[{': '.join(description)}]")

  address_type = get_address_type(address)

  target.scans[scan_ID] = Scan(
    target,
    address,
    port,
    description,
    freeze_variables(scan_definition.command)
  )
  
async def scan_services(target: Target):

  address = target.address

  log(f"[{address}]\tstarted")

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

def parse_result_file(base_directory, result_file, targets, unique_services, scan_filters):
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

    log(f"host: {address} ({','.join(target.hostnames)})")

    for port in host.findall('./ports/port/state[@state="open"]/..'):
      transport_protocol = port.get('protocol')
      port_ID = port.get('portid')

      service_tuple = (address, transport_protocol, port_ID)

      if service_tuple in unique_services:
        continue

      log(f"service: {service_tuple}")
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
          log(f"'{application_protocol}' is tunneled through '{service.get('tunnel')}'")
          application_protocol = service.get('tunnel') + '|' + application_protocol

        descriptions = []
        if service.get('product'):
          descriptions.append(service.get('product'))
        if service.get('version'):
          descriptions.append(service.get('version'))
        if service.get('extrainfo'):
          descriptions.append(service.get('extrainfo'))

        description = " ".join(descriptions)

      match_count = 0
      for filter_key, filter_pattern in scan_filters:
        if filter_key == 'host' and re.fullmatch(filter_pattern, address):
          log(f"{filter_key} '{address}' matches '{filter_pattern}'")
          match_count += 1
          continue

        if filter_key == 'protocol' and re.fullmatch(filter_pattern, transport_protocol):
          log(f"{filter_key} '{transport_protocol}' matches '{filter_pattern}'")
          match_count += 1
          continue

        if filter_key == 'port' and re.fullmatch(filter_pattern, port_ID):
          log(f"{filter_key} '{port_ID}' matches '{filter_pattern}'")
          match_count += 1
          continue

        if filter_key == 'service' and re.fullmatch(filter_pattern, application_protocol):
          log(f"{filter_key} '{application_protocol}' matches '{filter_pattern}'")
          match_count += 1
          continue

      if match_count == len(scan_filters):
        log("targeting service")

        target.services.append(
          Service(
            transport_protocol,
            port_ID,
            application_protocol,
            description
          )
        )

def parse_result_files(base_directory, result_files, scan_filters):
  targets = {}

  # a service is uniquely identified by the tuple (host, transport protocol, port number)
  unique_services = []

  for result_file in result_files:
    print(f"parsing '{result_file}' ...")
    log(f"parsing '{result_file}' ...")
    parse_result_file(base_directory, result_file, targets, unique_services, scan_filters)

  # filter targets with at least 1 service
  return {adr: target for adr, target in targets.items() if len(target.services) > 0}

def update_scan_config(scan_config, new_scan_config):
  log(f"updating scan '{scan_config['name']}' ...")

  if 'transport_protocol' in new_scan_config:
    log(f"updating transport protocol regex: '{new_scan_config['transport_protocol']}'")
    scan_config['transport_protocol'] = new_scan_config['transport_protocol']

  if 'application_protocol' in new_scan_config:
    log(f"updating application protocol regex: '{new_scan_config['application_protocol']}'")
    scan_config['application_protocol'] = new_scan_config['application_protocol']

  if 'command' in new_scan_config:
    log(f"updating command: '{new_scan_config['command']}'")
    scan_config['command'] = new_scan_config['command']

  if 'run_once' in scan_config:
    log(f"updating run-once flag: '{new_scan_config['run_once']}'")
    scan_config['run_once'] = new_scan_config['run_once']

def update_service_config(service_config, new_service_config):
  log(f"updating service '{service_config['name']}' ...")

  if 'transport_protocol' in new_service_config:
    log(f"updating transport protocol regex: '{new_service_config['transport_protocol']}'")
    service_config['transport_protocol'] = new_service_config['transport_protocol']

  if 'application_protocol' in new_service_config:
    log(f"updating application protocol regex: '{new_service_config['application_protocol']}'")
    service_config['application_protocol'] = new_service_config['application_protocol']

  if 'scans' not in new_service_config:
    return

  if 'scans' not in service_config:
    log("setting scans")
    service_config['scans'] = new_service_config['scans']
    return

  for scan_config in new_service_config['scans']:
    scan_name = scan_config['name']
    log(f"scan name: '{scan_name}'")

    append_config = True
    for sc in service_config['scans']:
      if sc['name'] == scan_name:
        update_scan_config(sc, scan_config)
        append_config = False
        break

    if append_config:
      log("appending scan")
      service_config['scans'].append(scan_config)

def update_config(config, new_config):
  if 'globals' in new_config:
    # https://peps.python.org/pep-0584/
    config['globals'] |= new_config['globals']

  if 'services' not in new_config:
    return

  if 'services' not in config:
    config['services'] = new_config['services']
    return

  for service_config in new_config['services']:
    service_name = service_config['name']

    append_config = True
    for sc in config['services']:
      if sc['name'] == service_name:
        update_service_config(sc, service_config)
        append_config = False
        break

    if append_config:
      log(f"appending service '{service_name}'")
      config['services'].append(service_config)

def load_config(config_files):
  config = None

  log(f"loading default configuration file '{PATH_TO_DEFAULT_CONFIG_FILE}' ...")

  if not PATH_TO_DEFAULT_CONFIG_FILE.exists():
    log("the file does not exist")
    sys.exit("the default configuration file does not exist!")

  with open(PATH_TO_DEFAULT_CONFIG_FILE, 'rb') as f:
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
      log("overwriting config")
      config = new_config
    else:
      log("updating config ...")
      update_config(config, new_config)

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

  if not os.geteuid() == 0 and not (args.ignore_uid or DRY_RUN):
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

  if len(args.filter):
    OVERWRITE = True

  global TARGETS
  TARGETS = parse_result_files(base_directory, args.input, args.filter)
  log(f"parsed {len(TARGETS)} targets")

  # find suitable scans for each target and queue them for later.
  # this has to be done outside any subthread/task,
  # so that the total number of scans is know from the start.
  for target in TARGETS.values():
    # iterate over the services found to be running on the target
    for service in target.services:
      transport_protocol = service.transport_protocol
      application_protocol = service.application_protocol

      suitable_scans = find_suitable_scans(transport_protocol, application_protocol)

      # mark the service as "scanned" if at least 1 suitable scan was found; even though there is not even a scan scheduled yet
      service.scanned = (len(suitable_scans) > 0)

      # iterate over each suitable scan and queue it for later
      for scan_definition in suitable_scans:
        if scan_definition.service in ('http', 'tls'):
          queue_service_scan_hostname(target, service, scan_definition)
        else:
          queue_service_scan_address(target, service, scan_definition)

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

def scan_filter(arg):
  key_value_pattern = re.compile(r'(host|protocol|port|service)=(.+)')

  m = key_value_pattern.fullmatch(arg)
  if not m:
    raise argparse.ArgumentTypeError(f"scan filter '{arg}' does not match '{key_value_pattern.pattern}'")

  return (m.group(1), m.group(2))

def int_greater_than_0(arg):
  try:
    i = int(arg)
  except ValueError:
    raise argparse.ArgumentTypeError("must be an integer number")

  if i < 1:
    raise argparse.ArgumentTypeError("must be greater than 0")

  return i

def main():
  parser = argparse.ArgumentParser(
    description = "Schedule and execute various tools based on the findings of an Nmap service scan."
  )

  parser.add_argument(
    'input',
    metavar = 'path',
    help = "path to the Nmap scan result file (e.g. 'nmap/services.xml')",
    type = pathlib.Path,
    nargs = '+',
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
    help = f"path to additional scanner configuration; default ('{PATH_TO_DEFAULT_CONFIG_FILE}') will be loaded first",
    type = pathlib.Path,
    nargs = '+'
  )

  parser.add_argument(
    '-t', '--concurrent-targets',
    metavar = 'number',
    help = "number of targets that should be scanned concurrently (default: 3)",
    type = int_greater_than_0,
    default = 3
  )

  parser.add_argument(
    '-s', '--concurrent-scans',
    metavar = 'number',
    help = "number of scans that should be running concurrently on a single target (default: 2)",
    type = int_greater_than_0,
    default = 2
  )

  parser.add_argument(
    '-m', '--max-time',
    metavar = 'seconds',
    help = f"maximum time in seconds each scan is allowed to take (default: {MAX_TIME})",
    type = int_greater_than_0,
    default = MAX_TIME
  )

  parser.add_argument(
    '-n', '--dry-run',
    help = "do not run any command; just create/update the 'commands.csv' file",
    action = 'store_true'
  )

  parser.add_argument(
    '-f', '--filter',
    metavar = 'key=regex',
    help = "only scan specific services that match all provided filters for host/protocol/port/service; existing result files will be overwritten",
    type = scan_filter,
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
  number_of_targets = 0
  number_of_scans = 0
  number_of_completed_scans = 0
  number_of_scanned_targets = 0
  for target in TARGETS.values():
    number_of_scans += len(target.scans)
    if target.number_of_scans_completed:
      number_of_scanned_targets += 1
      number_of_completed_scans += target.number_of_scans_completed

    if len(target.scans):
      number_of_targets += 1

      for scan in target.scans.values():
        if scan.completed and scan.return_code != 0:
          unsuccessful_scans.append(scan.command)

  if QUITTING:
    print("user aborted: some scans might have been killed before they were finished.")

  if number_of_targets == 0:
    sys.exit("nothing to scan")

  print(f"recon scanner ran {end_time - start_time} (hours:minutes:seconds).")

  print(f"{number_of_scanned_targets} of {number_of_targets} targets were scanned ({number_of_scanned_targets / number_of_targets:.1%}).")

  if number_of_scans:
    print(f"{number_of_completed_scans} of {number_of_scans} scans completed ({number_of_completed_scans / number_of_scans:.1%}).")

  if len(unsuccessful_scans):
    print(f"{len(unsuccessful_scans)} of those scans returned an error, ran into a timeout or were cancelled.")
