#!/usr/bin/env python3

#  The file is part of the perf_root Project.
#
#  The perf_root Project is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  The perf_root Project is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#  Copyright (C) 2020, Andrew McConachie, <andrew@depht.com>

import argparse
import datetime
import dns.exception
import dns.message
import dns.resolver
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.query
#import hashlib
import ipaddress
import itertools
import json
import os
from multiprocessing.pool import ThreadPool
import random
#import re
import signal
import socket
import statistics
import subprocess
import sys
import time

###########
# GLOBALS #
###########
# Logging constants
LOG_ERROR = 0
LOG_WARN = 1
LOG_INFO = 2
LOG_DEBUG = 3
LOG_OUTPUT = 'tty' # 'tty' | 'file' | False
LOG_FNAME = 'perf_root.log'
LOG_SIZE = 1024 # Max logfile size in KB

SIG_CHARS = 7 # How many significant characters to display in fancy output
SYS_TYPE = '' # Enumerated type of system we're running on: linux, bsd, darwin, win32, cygwin
TRACEROUTE_NUM_TIMEOUTS = 5 # Number of consecutive timed out traceroute probes we tolerate before giving up
ROOT_SERVERS = [] # Our list of DNS root servers

###########
# Classes #
###########
class RootServer():
  def __init__(self, name, ipv4, ipv6):
    self.name = name
    self.ipv4 = ipv4
    self.ipv6 = ipv6
    self.times_v4 = {}
    self.times_v6 = {}
    self.traceroute_v4 = []
    self.traceroute_v6 = []

  def __repr__(self):
    return "ipv4:" + str(self.ipv4) + " ipv6:" + str(self.ipv6) + " times_v4:" + repr(self.times_v4) + " times_v6:" + repr(self.times_v6)

  # Add a testing time for IPv4
  # Takes a protocol(udp/tcp), TLD and a time
  def add_time_v4(self, proto, tld, time):
    if not proto in self.times_v4:
      self.times_v4[proto] = {}

    if not tld in self.times_v4[proto]:
      self.times_v4[proto][tld] = [time]
    else:
      self.times_v4[proto][tld].append(time)

  # Add a testing time for IPv6
  # Takes a protocol(udp/tcp), TLD and a time
  def add_time_v6(self, proto, tld, time):
    if not proto in self.times_v6:
      self.times_v6[proto] = {}

    if not tld in self.times_v6[proto]:
      self.times_v6[proto][tld] = [time]
    else:
      self.times_v6[proto][tld].append(time)

  # Return list of all IPv4 testing times
  def get_flattened_times_v4(self):
    if len(self.times_v4) == 0:
      return [0.0]
    else:
      rv = []
      for proto in self.times_v4:
        rv += sum(list(self.times_v4[proto].values()), [])
      return rv

  # Return list of all IPv6 testing times
  def get_flattened_times_v6(self):
    if len(self.times_v6) == 0:
      return [0.0]
    else:
      rv = []
      for proto in self.times_v6:
        rv += sum(list(self.times_v6[proto].values()), [])
      return rv

  # Convert this object to JSON and return it
  def to_json(self):
    rv = {}
    rv['rsi'] = self.name
    rv['ipv4'] = self.times_v4
    rv['ipv6'] = self.times_v6
    rv['traceroute_v4'] = self.traceroute_v4
    rv['traceroute_v6'] = self.traceroute_v6
    return json.dumps(rv)

####################
# GLOBAL FUNCTIONS #
####################
def euthanize(signal, frame):
  sys.stdout.write("\rSIG-" + str(signal) + " caught, exiting\n")
  sys.stdout.flush()
  sys.exit(1)

def death(errStr=''):
  sys.stdout.write("\rFATAL:" + errStr + "\n")
  sys.stdout.flush()
  sys.exit(1)

# Logs message to LOG_FNAME or tty
def dbgLog(lvl, dbgStr):
  if not LOG_OUTPUT:
    return

  if lvl > LOG_LEVEL:
    return

  logPrefix = {
    LOG_ERROR: "Err",
    LOG_WARN: "Wrn",
    LOG_INFO: "Inf",
    LOG_DEBUG: "Dbg",
  }

  dt = datetime.datetime.now()
  ts = dt.strftime("%H:%M:%S.%f")
  outStr = ts + "> " + logPrefix[lvl] + "> " + dbgStr.strip()

  if LOG_OUTPUT == 'file':
    global LOG_HANDLE
    try:
      if int(os.stat(LOG_FNAME).st_size / 1024) < LOG_SIZE:
        LOG_HANDLE.write(outStr + '\n')
      else:
        LOG_HANDLE.close()
        try:
          LOG_HANDLE = open(LOG_FNAME, 'w', 1)
          LOG_HANDLE.write(outStr + '\n')
        except IOError:
          death("IOError writing to debug file " + LOG_FNAME)

    except IOError:
      death("IOError writing to debug file " + LOG_FNAME)
  elif LOG_OUTPUT == 'tty':
    print(outStr)

# Fancier output than normal debug logging
# Takes a delay in seconds to wait after string(ss) is printed
def fancy_output(delay, ss):
  window = 70

  # Only triggers on WARN and INFO log levels
  if LOG_LEVEL >= LOG_DEBUG or LOG_LEVEL <= LOG_ERROR:
    return

  if len(ss) > window:
    dbgLog(LOG_ERROR, "fancy_output: print window exceeded")
    return

  sys.stdout.write(ss)
  for ii in range(window - len(ss)):
    sys.stdout.write(' ')

  sys.stdout.flush()
  time.sleep(delay)

# Send a single walk query and return a dnspython response message
def send_walk_query(qstr):
  query = dns.message.make_query(qstr.lower(), 'NS', want_dnssec=True)
  server = str(random.choice(ROOT_SERVERS).ipv4)
  dbgLog(LOG_DEBUG, "Using server:" + server)

  try:
    rv = dns.query.udp(query, server, ignore_unexpected=True, timeout=args.query_timeout)
  except dns.exception.Timeout:
    dbgLog(LOG_ERROR, "send_walk_query: query timeout " + qstr)
    return None
  except dns.query.BadResponse:
    dbgLog(LOG_ERROR, "send_walk_query: bad response " + qstr)
    return None

  return rv

# Process the response from a DNS walk query
# Return the two adjacent domain names for NXDOMAIN
# Return the same name twice for NOERROR
# Return None None for everything else, including when we get to the end of the zone
def handle_walk_response(resp):
  if resp.rcode() == 3 and resp.opcode() == 0: # NXDOMAIN
    for rr in resp.authority:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NSEC:
        k1 = rr.to_text().split()[0].rstrip('.')
        k2 = rr.to_text().split()[4].rstrip('.')
        if len(k1) == 0: # Ignore the zone apex NSEC RR
          continue
        dbgLog(LOG_DEBUG, "k1:" + k1 + " k2:" + k2)
        return k1, k2
    for rr in resp.answer:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NSEC:
        k1 = rr.to_text().split()[0].rstrip('.')
        k2 = rr.to_text().split()[4].rstrip('.')
        if len(k1) == 0: # Ignore the zone apex NSEC RR
          continue
        dbgLog(LOG_DEBUG, "k1:" + k1 + " k2:" + k2)
        return k1, k2

  elif resp.rcode() == 0 and resp.opcode() == 0: # NOERROR
    for rr in resp.authority:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NS:
        ns = rr.to_text().split()[0].rstrip('.')
        dbgLog(LOG_DEBUG, "ns:" + ns)
        return ns, ns
    for rr in resp.answer:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NS:
        ns = rr.to_text().split()[0].rstrip('.')
        dbgLog(LOG_DEBUG, "ns:" + ns)
        return ns, ns

  else: # Need to handle SERVFAIL
    dbgLog(LOG_WARN, "handle_walk_response unhandled response:" + str(resp))

  return None, None

# Iteratively find X tlds surrounding qstr
# Returns list of X tlds alpha sorted
def find_tlds(qstr, x):
  dbgLog(LOG_DEBUG, "find_tlds:" + qstr + " x:" + str(x))
  tlds = {}

  # The first time is special
  resp = send_walk_query(qstr)
  if not resp:
    death("First DNS query failed " + qstr)

  dn_down, dn_up = handle_walk_response(resp)
  if not dn_down or not dn_up:
    dn_down = qstr
    dn_up = qstr
  else:
    tlds[dn_down] = True
    tlds[dn_up] = True
    dn_down = dn_dec(dn_down)
    dn_up = dn_inc(dn_up)

  # Keep going until we find x TLDs or all TLDs
  going_up = True
  going_down = True
  while True:
    dbgLog(LOG_DEBUG, "find_tlds_while dn_down:" + dn_down + " dn_up:" + dn_up + " len_tlds:" + str(len(tlds)))
    if len(tlds) >= x or not going_down and not going_up:
      return sorted(tlds)[:x]

    if going_down:
      resp = send_walk_query(dn_down)
      if resp == None:
        dbgLog(LOG_WARN, "find_tlds walk_down query failed for " + qstr)
        continue
      else:
        dn_down, _ = handle_walk_response(resp)
      if dn_down == None:
        dbgLog(LOG_DEBUG, "find_tlds finished walking down")
        going_down = False
        dn_down = '.'
      else:
        if len(dn_down) > 0:
          tlds[dn_down] = True
        dn_down = dn_dec(dn_down)

    if going_up:
      resp = send_walk_query(dn_up)
      if resp == None:
        dbgLog(LOG_WARN, "find_tlds walk_up query failed for " + qstr)
        continue
      else:
        _, dn_up = handle_walk_response(resp)
      if dn_up == None:
        dbgLog(LOG_WARN, "find_tlds finished walking up")
        going_up = False
        dn_up = '.'
      else:
        if len(dn_up) > 0:
          tlds[dn_up] = True
        dn_up = dn_inc(dn_up)

# Increment a domain name for walking
def dn_inc(dn):
  if len(dn) < 63: # Maximum DNS label length == 63
    return dn + 'a'
  else:
    if ord(dn[-1:]) == 122: # lowercase 'z'
      return dn_inc(dn[:-1]) + 'z'
    else:
      return dn[:-1] + chr(ord(dn[-1:]) + 1)

# Decrement a domain name for walking
def dn_dec(dn):
  if len(dn) == 1: # min len == 1
    if dn == 'a':
      return 'a' # nothing comes before 'a'
    else:
      return chr(ord(dn[0] - 1))
  else:
    if dn[-1:] == 'a':
      return dn[:-1]
    else:
      if len(dn) < 63:
        return dn[:-1] + chr(ord(dn[-1:]) - 1) + 'z'
      else:
        return dn[:-1] + chr(ord(dn[-1:]) - 1)

# Time the query and response to a root server IP address(v4/v6)
# Takes a function for the type of query(TCP/UDP), a TLD to query, and an IP address
# Returns time in seconds as float and -1 on failure
def timed_query(fn, tld, ip):
  query = dns.message.make_query(tld, 'NS')

  start_time = time.perf_counter()
  try:
    fn(query, str(ip), timeout=args.query_timeout)
  except dns.exception.Timeout:
    dbgLog(LOG_WARN, "timed_query: timeout " + fn.__name__ + " " + tld + " ip:" + str(ip))
    return -1
  except dns.query.BadResponse:
    dbgLog(LOG_WARN, "timed_query: bad response " + fn.__name__ + " " + tld + " ip:" + str(ip))
    return -1
  except:
    dbgLog(LOG_WARN, "timed_query: general error " + fn.__name__ + " " + tld + " ip:" + str(ip))
    return -1

  dbgLog(LOG_DEBUG, "timed_query " + tld + " " + str(ip) + " " + str(time.perf_counter() - start_time))
  return time.perf_counter() - start_time

# Perform a traceroute
# Takes a traceroute binary location(type:string) and an IP address(type:ipaddress)
# Returns list of lists of gateways(type:string)
def trace_route(binary, ip): # Only tested with Linux thus far

  # Parses each line returned from traceroute cmd
  # Takes a line
  # Returns list of gateways returning probes
  # Returns None if no probes sent
  # Returns empty list if no probes received
  def parse_line(line): 
    gateways = []
    for token in line.strip().split()[1:]:
      try:
        if token == 'to': # Don't match the first line
          return None
        gw = ipaddress.ip_address(token)
        gateways.append(token)
      except ValueError:
        continue
    return gateways

  # Delay start time to prevent packet drops at first gateway
  time.sleep(random.randint(0, int(len(ROOT_SERVERS) / 3)) * 2)

  cmd = binary + " -n " + str(ip)
  dbgLog(LOG_INFO, "trace_route:" + cmd)
  try:
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)

    # Keep reading lines until we run out or reach TRACEROUTE_NUM_TIMEOUTS
    rv = []
    timeouts = 0
    while True:
      line = proc.stdout.readline()
      if not line:
        if proc.poll() == None:
          proc.terminate()
        return rv

      gateways = parse_line(line)
      if isinstance(gateways, list):
        if len(gateways) == 0:
          timeouts += 1
        else:
          timeouts = 0

        # Have we reached our max allowed timeouts?
        if timeouts == TRACEROUTE_NUM_TIMEOUTS:
          if proc.poll() == None:
            proc.terminate()
          return rv[:-TRACEROUTE_NUM_TIMEOUTS + 1]
        else:
          rv.append(gateways)

  except subprocess.TimeoutExpired as e:
    dbgLog(LOG_ERROR, "trace_route subprocess TimeoutExpired" + str(e))
    raise
  except subprocess.CalledProcessError as e:
    dbgLog(LOG_ERROR, "trace_route subprocess CallProcessError" + str(e))
    raise

# Parse the root-hints file and return a list of RSIs
# TODO: Write a proper parser using dnspython
def parse_root_hints(root_hints):
  rv = []
  fn = open(root_hints, 'r')
  name = ipv4 = ipv6 = None
  for line in fn:
    if line.split()[0] == ';':
      continue
    elif line.split()[0] == '.':
      name = line.split()[3].strip('.').lower()
    else:
      ip = ipaddress.ip_address(line.split()[3])

      if ip.version == 4:
        ipv4 = ip
      elif ip.version == 6:
        ipv6 = ip

    if name and ipv4 and ipv6:
      rv.append(RootServer(name, ipv4, ipv6))
      name = ipv4 = ipv6 = None

  fn.close()
  return rv

# Returns the type of system we are running on
# Returns either: linux, bsd, darwin, win32, cygwin
def get_sys_type():
  if sys.platform.lower().startswith('freebsd'):
    return 'bsd'
  elif sys.platform.lower().startswith('netbsd'):
    return 'bsd'
  elif sys.platform.lower().startswith('openbsd'):
    return 'bsd'
  elif sys.platform.lower().startswith('linux'):
    return 'linux'
  elif sys.platform.lower().startswith('darwin'):
    return 'darwin'
  elif sys.platform.lower().startswith('win32'):
    death('Unsupported platform win32')
    #return 'win32'
  elif sys.platform.lower().startswith('cygwin'):
    death('Unsupported platform cygwin')
    #return 'cygwin'

# Returns the location of an executable binary
# Returns None if binary cannot be found
# Must be called after SYS_TYPE is set
def find_binary(fn):
  def test(path): # Returns true if passed file exists and is executable by current user
    if os.path.exists(path):
      if os.access(path, os.X_OK):
        return True
    return False

  if SYS_TYPE == 'bsd' or SYS_TYPE == 'linux' or SYS_TYPE == 'darwin':
    for directory in ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/usr/local/bin/', '/usr/local/sbin/']:
      if test(directory + fn):
        return directory + fn
    return None

  elif SYS_TYPE == 'win32':
    death('Unsupported platform win32')

  elif SYS_TYPE == 'cygwin':
    death('Unsupported platform cygwin')


###################
# BEGIN EXECUTION #
###################
# Enable file debugging if enabled
if LOG_OUTPUT == 'file':
  try:
    LOG_HANDLE = open(LOG_FNAME, 'w', 1)
  except:
    death("Unable to open debug log file")

# Set signal handlers
signal.signal(signal.SIGINT, euthanize)
signal.signal(signal.SIGTERM, euthanize)
signal.signal(signal.SIGABRT, euthanize)
signal.signal(signal.SIGALRM, euthanize)
signal.signal(signal.SIGSEGV, euthanize)
signal.signal(signal.SIGHUP, euthanize)

# CLI options
ap = argparse.ArgumentParser(description = 'Test DNS Root Servers',
                               formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                               epilog = 'If --out-file is not specified stdout is used.')
ap.add_argument('-d', '--delay', type=float, action='store', default=0.05,
                  dest='delay', help='Delay between each test cycle in seconds')
ap.add_argument('-n', '--num-tlds', type=int, action='store', default=10,
                  dest='num_tlds', help='Number of TLDs to test')
ap.add_argument('-o', '--out-file', type=str, action='store', default='',
                  dest='out_file', help='Filename for output')
ap.add_argument('-q', '--query-timeout', type=int, action='store', default=10,
                  dest='query_timeout', help='DNS query timeout in seconds')
ap.add_argument('-r', '--root-hints', type=str, action='store', default='named.cache',
                  dest='root_hints', help='Root hints file')
ap.add_argument('-t', '--num-tests', type=int, action='store', default=2,
                  dest='num_tests', help='Number of test cycles per-TLD')
ap.add_argument('-v', '--verbose', action='count', default=0,
                  dest='verbose', help='Verbose output, repeat for increased verbosity')

# A high num_threads value can cause dropped traceroute probes at first gateway
ap.add_argument('--threads', type=int, action='store', default=4, 
                  dest='num_threads', help='Number of test threads to run concurrently')

ap.add_argument('--no-tcp', action='store_true', default=False, # Toggle UDP/TCP testing off
                  dest='no_tcp', help='Turn off TCP testing')
ap.add_argument('--no-udp', action='store_true', default=False,
                  dest='no_udp', help='Turn off UDP testing')

ap.add_argument('--no-ipv4', action='store_true', default=False, # Toggle IPv4/IPv6 testing off
                  dest='no_v4', help='Turn off IPv4 testing')
ap.add_argument('--no-ipv6', action='store_true', default=False,
                  dest='no_v6', help='Turn off IPv6 testing')

ap.add_argument('--no-traceroute', action='store_true', default=False,
                  dest='no_traceroute', help='Turn off IPv4 and IPv6 traceroute')

args = ap.parse_args()

LOG_LEVEL = min(args.verbose, LOG_DEBUG)
dbgLog(LOG_INFO, "Begin Execution")

if args.no_v4 and args.no_v6:
  death("Both IPv4 and IPv6 disabled")

if args.no_udp and args.no_tcp:
  death("Both TCP and UDP disabled")

SYS_TYPE = get_sys_type() # Determine what the OS is
dbgLog(LOG_INFO, "SYS_TYPE:" + SYS_TYPE)
ROOT_SERVERS = parse_root_hints(args.root_hints) # Get our list of root servers

# Is IPv6 supported on this host?
if not args.no_v6:
  IPV6_SUPPORT = True
  try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect( (str(random.choice(ROOT_SERVERS).ipv6), 53) )
    s.close()
  except:
    dbgLog(LOG_INFO, "No local IPv6 configured")
    IPV6_SUPPORT = False

if args.no_v4 and not IPV6_SUPPORT:
  death("IPv4 disabled and IPv6 not configured")

random.seed()
# This ranges from 'aa' to 'zz'
tlds = find_tlds(chr(random.randint(97, 122)) + chr(random.randint(97, 122)), args.num_tlds)
fancy_output(1, "Found " + str(len(tlds)) + " TLDs")

# Our pool of worker threads
pool = ThreadPool(processes=args.num_threads)

# Perform IPv4 tests
if not args.no_v4:
  ipv4_addresses = [rsi.ipv4 for rsi in ROOT_SERVERS]

  if not args.no_traceroute:
    fancy_output(0, "\rRunning traceroute with " + str(args.num_threads) + " threads")
    traces = pool.starmap(trace_route, zip(itertools.repeat(find_binary('traceroute')), ipv4_addresses))
    dbgLog(LOG_DEBUG, "traceroute results: " + repr(traces))
    for rsi,trace in zip(ROOT_SERVERS, traces):
      rsi.traceroute_v4 = trace

  fancy_output(0.5, "\rRunning IPv4 DNS queries with " + str(args.num_threads) + " threads")
  dbgLog(LOG_INFO, "Running IPv4 DNS queries with " + str(args.num_threads) + " threads")
  for ii in range(1, args.num_tests + 1):
    times_v4 = []
    if not args.no_udp:
      udp_times = pool.starmap(timed_query, [[dns.query.udp, tld, ip] for tld, ip in itertools.product(tlds, ipv4_addresses)])
      times_v4 += udp_times
      for tld in tlds:
        for rsi in ROOT_SERVERS:
            rsi.add_time_v4('udp', tld, udp_times.pop(0))

    if not args.no_tcp:
      tcp_times = pool.starmap(timed_query, [[dns.query.tcp, tld, ip] for tld, ip in itertools.product(tlds, ipv4_addresses)])
      times_v4 += tcp_times
      for tld in tlds:
        for rsi in ROOT_SERVERS:
            rsi.add_time_v4('tcp', tld, tcp_times.pop(0))

    mean = str(statistics.mean(times_v4))[:SIG_CHARS]
    minimum = str(min(times_v4))[:SIG_CHARS]
    maximum = str(max(times_v4))[:SIG_CHARS]
    fancy_output(args.delay, "\rIPv4 test cycle " + str(ii) + " min:" + minimum + " max:" + maximum + " avg:" + mean)

# Perform IPv6 tests
if not args.no_v6 and IPV6_SUPPORT:
  ipv6_addresses = [rsi.ipv6 for rsi in ROOT_SERVERS]

  if not args.no_traceroute:
    fancy_output(0, "\rRunning traceroute6 with " + str(args.num_threads) + " threads")
    traces = pool.starmap(trace_route, zip(itertools.repeat(find_binary('traceroute6')), ipv6_addresses))
    dbgLog(LOG_DEBUG, "traceroute6 results: " + repr(traces))
    for rsi,trace in zip(ROOT_SERVERS, traces):
      rsi.traceroute_v6 = trace

  fancy_output(0.5, "\rRunning IPv6 DNS queries with " + str(args.num_threads) + " threads")
  dbgLog(LOG_INFO, "Running IPv6 DNS queries with " + str(args.num_threads) + " threads")
  for ii in range(1, args.num_tests + 1):
    times_v6 = []
    if not args.no_udp:
      udp_times = pool.starmap(timed_query, [[dns.query.udp, tld, ip] for tld, ip in itertools.product(tlds, ipv6_addresses)])
      times_v6 += udp_times
      for tld in tlds:
        for rsi in ROOT_SERVERS:
            rsi.add_time_v6('udp', tld, udp_times.pop(0))

    if not args.no_tcp:
      tcp_times = pool.starmap(timed_query, [[dns.query.tcp, tld, ip] for tld, ip in itertools.product(tlds, ipv6_addresses)])
      times_v6 += tcp_times
      for tld in tlds:
        for rsi in ROOT_SERVERS:
            rsi.add_time_v6('tcp', tld, tcp_times.pop(0))

    mean = str(statistics.mean(times_v6))[:SIG_CHARS]
    minimum = str(min(times_v6))[:SIG_CHARS]
    maximum = str(max(times_v6))[:SIG_CHARS]
    fancy_output(args.delay, "\rIPv6 test cycle " + str(ii) + " min:" + minimum + " max:" + maximum + " avg:" + mean)

fancy_output(0, "\rFinished testing")
print()

# Create output and write it
output = ''
for rsi in ROOT_SERVERS:
  output += rsi.to_json()

if len(args.out_file) > 0:
  try:
    fh = open(args.out_file, 'w')
    fh.write(output)
    fh.close()
  except:
    death("Unable to write to " + args.out_file)
else:
  print(output)

sys.exit(0)
