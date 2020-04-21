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
import multiprocessing.pool
import random
#import re
import signal
import socket
import statistics
import subprocess
import sys
import threading
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
DNS_MAX_QUERIES = 5 # Number of query retries before we give up
ROOT_SERVERS = [] # Our list of DNS root servers
DYING = False # Are we in the process of dying

STATIC_SERVERS = [ # Only used to discover actual RSIs if local recursive resolution fails
{'a': '198.41.0.4', 'aaaa': '2001:503:ba3e::2:30'},
{'a': '199.9.14.201', 'aaaa': '2001:500:200::b'},
{'a': '192.33.4.12', 'aaaa': '2001:500:2::c'},
{'a': '199.7.91.13', 'aaaa': '2001:500:2d::d'},
{'a': '192.203.230.10', 'aaaa': '2001:500:a8::e'},
{'a': '192.5.5.241', 'aaaa': '2001:500:2f::f'},
{'a': '192.112.36.4', 'aaaa': '2001:500:12::d0d'},
{'a': '198.97.190.53', 'aaaa': '2001:500:1::53'},
{'a': '192.36.148.17', 'aaaa': '2001:7fe::53'},
{'a': '192.58.128.30', 'aaaa': '2001:503:c27::2:30'},
{'a': '193.0.14.129', 'aaaa': '2001:7fd::1'},
{'a': '199.7.83.42', 'aaaa': '2001:500:9f::42'},
{'a': '202.12.27.33', 'aaaa': '2001:dc3::35'}
]

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
    return "name:" + self.name + " ipv4:" + str(self.ipv4) + " ipv6:" + str(self.ipv6) + " times_v4:" + repr(self.times_v4) + " times_v6:" + repr(self.times_v6)

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

    self.anonymize_traceroutes()
    rv['traceroute_v4'] = self.traceroute_v4
    rv['traceroute_v6'] = self.traceroute_v6
    return json.dumps(rv)

  # Anonymizes IP addresses in traceroutes
  # Currently only replaces private IP space with generic stub IP
  def anonymize_traceroutes(self):
    for ii, hops in enumerate(self.traceroute_v4):
      self.traceroute_v4[ii] = \
        ['10.0.0.1' if ipaddress.ip_address(hop).is_private else hop for hop in self.traceroute_v4[ii]]

    for ii, hops in enumerate(self.traceroute_v6):
      self.traceroute_v6[ii] = \
        ['fe80::1' if ipaddress.ip_address(hop).is_private else hop for hop in self.traceroute_v6[ii]]

####################
# GLOBAL FUNCTIONS #
####################
# Threadsafe version of death() for signal handling
def euthanize(signal, frame):
  if threading.current_thread() != threading.main_thread():
    return

  global DYING
  DYING = True

  #  for thr in threading.enumerate():
  #    if thr.is_alive():
  #      dbgLog(LOG_DEBUG, "Thread name:" + thr.name + " id:" + str(thr.ident) + " daemon:" + str(thr.daemon))

  sys.exit("SIG-" + str(signal) + " caught, exiting\n")

def death(errStr=''):
  global DYING
  DYING = True
  sys.exit("FATAL:" + errStr)

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
  window = 70 # Maximum length of ss
  min_len = 2 # Minimum length of ss

  # Only triggers on WARN and INFO log levels
  if LOG_LEVEL >= LOG_DEBUG or LOG_LEVEL <= LOG_ERROR:
    return

  if len(ss) < min_len:
    dbgLog(LOG_ERROR, "fancy_output: output too short")
    return

  if len(ss) > window:
    dbgLog(LOG_ERROR, "fancy_output: print window exceeded")
    return

  if ss[0] != '\r':
    ss = '\r' + ss

  sys.stdout.write(ss)
  for ii in range(window - len(ss)):
    sys.stdout.write(' ')

  sys.stdout.flush()
  time.sleep(delay)

# Send a single walk query and return a dnspython response message
def send_walk_query(qstr):
  if DYING:
    return None

  query = dns.message.make_query(qstr.lower(), 'NS', want_dnssec=True)
  server = str(random.choice(ROOT_SERVERS).ipv4)
  dbgLog(LOG_DEBUG, "Using server:" + server)

  try:
    rv = dns.query.udp(query, server, ignore_unexpected=True, timeout=args.query_timeout)
  except dns.exception.Timeout:
    dbgLog(LOG_WARN, "send_walk_query: query timeout " + server + " qname:" + qstr)
    return None
  except dns.query.BadResponse:
    dbgLog(LOG_WARN, "send_walk_query: bad response " + server + " qname:" + qstr)
    return None
  except dns.query.UnexpectedSource:
    dbgLog(LOG_WARN, "send_walk_query: bad source IP in response " + server + " qname:" + qstr)
    return None
  except dns.exception.DNSException as e:
    dbgLog(LOG_WARN, "send_walk_query: general dns error " + server + " " + str(e))
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
  for ii in range(DNS_MAX_QUERIES):
    resp = send_walk_query(qstr)
    if not resp:
      if ii == DNS_MAX_QUERIES:
        death("First DNS query failed " + str(DNS_MAX_QUERIES) + " times " + qstr)
    else:
      break

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
  query_attempts = 0
  while True:
    if query_attempts > DNS_MAX_QUERIES:
     dbgLog(LOG_DEBUG, "find_tlds_while DNS query failed " + str(DNS_MAX_QUERIES) + " times")
     death("Max query attempts exceeded")

    dbgLog(LOG_DEBUG, "find_tlds_while dn_down:" + dn_down + " dn_up:" + dn_up + " len_tlds:" + str(len(tlds)))
    if len(tlds) >= x or not going_down and not going_up:
      return sorted(tlds)[:x]

    if going_down:
      resp = send_walk_query(dn_down)
      if resp == None:
        dbgLog(LOG_WARN, "find_tlds walk_down query failed for " + qstr)
        query_attempts += 1
        continue
      else:
        query_attempts = 0
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
        query_attempts += 1
        continue
      else:
        query_attempts = 0
        _, dn_up = handle_walk_response(resp)
      if dn_up == None:
        dbgLog(LOG_DEBUG, "find_tlds finished walking up")
        going_up = False
        dn_up = '.'
      else:
        if len(dn_up) > 0:
          tlds[dn_up] = True
        dn_up = dn_inc(dn_up)

# Increment a domain name for walking
# We only handle alpha characters, which is fine for the root zone
def dn_inc(dn):
  if len(dn) < 1: # Defensive programming
    return 'a'
  if len(dn) < 63: # Maximum DNS label length == 63
    if dn[-1:] == 'z':
      if len(dn.strip('z')) == 0:
        return dn + 'a'
      else:
        return dn_inc(dn.rstrip('z'))
    else:
      return dn[:-1] + chr(ord(dn[-1:]) + 1)
  else:
    if dn[-1:] == 'z':
      if len(dn.strip('z')) == 0:
        return dn # Defensive programming
      else:
        return dn_inc(dn.rstrip('z'))
    else:
      return dn[:-1] + chr(ord(dn[-1:]) + 1)

# Decrement a domain name for walking
def dn_dec(dn):
  if len(dn) <= 1: # min len == 1
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
  if DYING:
    return -1

  query = dns.message.make_query(tld, 'NS')
  start_time = time.perf_counter()
  try:
    fn(query, str(ip), timeout=args.query_timeout)
  except dns.exception.Timeout:
    dbgLog(LOG_WARN, "timed_query: timeout qname:" + tld + " ip:" + str(ip) + ":" + fn.__name__)
    return -1
  except dns.query.BadResponse:
    dbgLog(LOG_WARN, "timed_query: bad response qname:" + tld + " ip:" + str(ip) + ":" + fn.__name__)
    return -1
  except dns.query.UnexpectedSource:
    dbgLog(LOG_WARN, "timed_query: bad source IP in response qname:" + tld + " ip:" + str(ip) + ":" + fn.__name__)
    return -1
  except dns.exception.DNSException as e:
    dbgLog(LOG_WARN, "timed_query: general dns error qname:" + tld + " ip:" + str(ip) + ":" + fn.__name__)
    return -1

  dbgLog(LOG_DEBUG, "timed_query " + tld + " " + str(ip) + " " + str(time.perf_counter() - start_time))
  return time.perf_counter() - start_time

# Perform a traceroute
# Takes a traceroute binary location(type:string) and an IP address(type:ipaddress)
# Returns list of lists of gateways(type:string)
def trace_route(binary, ip):

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

  if DYING:
    return []

  # Delay start time to prevent packet drops at first gateway
  time.sleep(random.uniform(1, args.num_threads))

  rv = []
  cmd = binary + " -n " + str(ip)
  dbgLog(LOG_INFO, "trace_route:" + cmd)
  try:
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)

    # Keep reading lines until we run out or reach TRACEROUTE_NUM_TIMEOUTS
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
    return rv
  except subprocess.CalledProcessError as e:
    dbgLog(LOG_ERROR, "trace_route subprocess CallProcessError" + str(e))
    return rv
  except OSError as e:
    dbgLog(LOG_ERROR, "trace_route subprocess OSError" + str(e))
    return rv
  except subprocess.SubprocessError:
    dbgLog(LOG_ERROR, "trace_route general subprocess error")
    return rv

# Returns list of RSIs if possible, otherwise returns None
# Uses locally configured resolver
def local_discover_root_servers():
  try:
    d = dns.resolver.Resolver()
  except dns.exception.DNSException as e:
    dbgLog(LOG_WARN, "Local resolver not found " + repr(e))
    return None

  try:
    resp = d.query('.', 'NS')
  except dns.exception.DNSException as e:
    dbgLog(LOG_WARN, "Failed to query local resolver for . " + repr(e))
    return None

  names = [str(name).strip('.').lower() for name in resp.rrset]

  rv = []
  for name in sorted(names):
    try:
      resp_a = d.query(name, 'A')
    except dns.exception.DNSException as e:
      dbgLog(LOG_WARN, "Failed querying A record for " + name + " " + repr(e))
      return None

    try:
      resp_aaaa = d.query(name, 'AAAA')
    except dns.exception.DNSException as e:
      dbgLog(LOG_WARN, "Failed querying AAAA record for " + name + " " + repr(e))
      return None

    rv.append(RootServer(name, str(resp_a.rrset[0]), str(resp_aaaa.rrset[0])))

  return rv

# Returns list of RSIs if possible, otherwise returns None
# Uses STATIC_SERVERS to find all servers
# Takes a function to use for querying(udp or tcp)
def auth_discover_root_servers(fn):
  random.shuffle(STATIC_SERVERS)

  # Because 'reasons' we may not get the full priming response in one query
  # So we construct it from multiple queries just to be sure
  discovered = []
  for server in STATIC_SERVERS:
    query = dns.message.make_query('.', 'NS')
    dest = server['a']
    dbgLog(LOG_DEBUG, "auth_discover_root_servers: Trying destination:" + dest)

    try:
      primer = fn(query, dest, timeout=args.query_timeout)
      dbgLog(LOG_DEBUG, repr(primer.section_from_number(3)))
    except dns.exception.Timeout:
      dbgLog(LOG_WARN, "auth_discover_root_servers: query timeout " + dest)
      continue
    except dns.query.BadResponse:
      dbgLog(LOG_WARN, "auth_discover_root_servers: bad response " + dest)
      continue
    except dns.query.UnexpectedSource:
      dbgLog(LOG_WARN, "auth_discover_root_servers: bad source IP in response " + dest)
      continue
    except dns.exception.DNSException as e:
      dbgLog(LOG_WARN, "auth_discover_root_servers: general dns error " + dest + " " + str(e))
      continue

    for rr in primer.section_from_number(3): # 3 == Additional
      name = rr.to_text().split()[0].strip('.')
      ip = rr.to_text().split()[4]

      if name not in [disc['dn'] for disc in discovered]:
        discovered.append({'dn': name})

      if ipaddress.ip_address(ip).version == 4:
        for disc in discovered:
          if disc['dn'] == name:
            disc['v4'] = ip
      else:
        for disc in discovered:
          if disc['dn'] == name:
            disc['v6'] = ip

    if len(discovered) == len(STATIC_SERVERS):
      done = True
      for disc in discovered:
        if 'v4' not in disc or 'v6' not in disc:
          done = False

      if done:
        return [RootServer(disc['dn'], disc['v4'], disc['v6']) for disc in discovered]
      
  return None

# Returns the type of system we are running on
# Returns either: linux, fbsd, nbsd, obsd, darwin, win32, cygwin
# For now we only support linux and fbsd
def get_sys_type():
  if sys.platform.lower().startswith('linux'):
    return 'linux'
  elif sys.platform.lower().startswith('freebsd'):
    return 'fbsd'
  elif sys.platform.lower().startswith('netbsd'):
    return 'nbsd'
  elif sys.platform.lower().startswith('openbsd'):
    return 'obsd'
  elif sys.platform.lower().startswith('darwin'):
    return 'darwin'
  elif sys.platform.lower().startswith('win32'):
    return 'win32'
  elif sys.platform.lower().startswith('cygwin'):
    return 'cygwin'

# Returns the location of an executable binary
# Returns None if binary cannot be found
# Must be called after SYS_TYPE is set
def find_binary(fn):
  def test(path): # Returns true if passed file exists and is executable by current user
    if os.path.exists(path):
      if os.access(path, os.X_OK):
        return True
    return False

  if SYS_TYPE == 'fbsd' or SYS_TYPE == 'linux':
    for directory in ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/usr/local/bin/', '/usr/local/sbin/']:
      if test(directory + fn):
        return directory + fn
    return None

  death('Unsupported platform' + SYS_TYPE)

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
signal.signal(signal.SIGFPE, euthanize)
signal.signal(signal.SIGILL, euthanize)

# win32
# https://bugs.python.org/issue26350
# https://bugs.python.org/issue23948
#signal.signal(signal.CTRL_BREAK_EVENT, euthanize)
#signal.signal(signal.CTRL_C_EVENT, euthanize)

# CLI options
args_epilog = "If --out-file is not specified stdout is used."

ap = argparse.ArgumentParser(description = 'Test DNS Root Servers',
                               formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                               epilog = args_epilog)
ap.add_argument('-d', '--delay', type=float, action='store', default=0.05,
                  dest='delay', help='Delay between each test cycle in seconds')
ap.add_argument('-n', '--num-tlds', type=int, action='store', default=10,
                  dest='num_tlds', help='Number of TLDs to query for')
ap.add_argument('-o', '--out-file', type=str, action='store', default='',
                  dest='out_file', help='Filename for output')
ap.add_argument('-q', '--query-timeout', type=int, action='store', default=10,
                  dest='query_timeout', help='DNS query timeout in seconds')
ap.add_argument('-t', '--num-tests', type=int, action='store', default=2,
                  dest='num_tests', help='Number of test cycles per-TLD')
ap.add_argument('-v', '--verbose', action='count', default=0,
                  dest='verbose', help='Verbose output, repeat for increased verbosity')

ap.add_argument('--threads', type=int, action='store', default=6, choices=[1,2,3,4,5,6],
                  dest='num_threads', help='Number of threads to run concurrently')

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
fancy_output(0, "\rBegin Execution")
random.seed()

if args.no_v4 and args.no_v6:
  death("Both IPv4 and IPv6 disabled")

if args.no_udp and args.no_tcp:
  death("Both TCP and UDP disabled")

SYS_TYPE = get_sys_type() # Determine what the OS is
dbgLog(LOG_INFO, "SYS_TYPE:" + SYS_TYPE)

# Find our root servers
ROOT_SERVERS = local_discover_root_servers()
if not ROOT_SERVERS:
  dbgLog(LOG_WARN, "Local resolution of root servers failed, attempting direct resolution via TCP.")
  ROOT_SERVERS = auth_discover_root_servers(dns.query.tcp)
if not ROOT_SERVERS:
  dbgLog(LOG_WARN, "Direct TCP queries to root servers failed, attempting direct resolution via UDP.")
  ROOT_SERVERS = auth_discover_root_servers(dns.query.udp)
if not ROOT_SERVERS:
  death("Unable to contact any root servers")

dbgLog(LOG_DEBUG, "Found " + str(len(ROOT_SERVERS)) + " root servers")
fancy_output(1, "\rFound " + str(len(ROOT_SERVERS)) + " root servers")

# Is IPv6 supported on this host?
if not args.no_v6:
  IPV6_SUPPORT = True
  try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect( (str(random.choice(ROOT_SERVERS).ipv6), 53) )
    s.close()
  except OSError:
    dbgLog(LOG_INFO, "No local IPv6 configured")
    IPV6_SUPPORT = False

if args.no_v4 and not IPV6_SUPPORT:
  death("IPv4 disabled and IPv6 not configured")

# This ranges from 'aa' to 'zz'
tlds = find_tlds(chr(random.randint(97, 122)) + chr(random.randint(97, 122)), args.num_tlds)
dbgLog(LOG_DEBUG, "Found " + str(len(tlds)) + " TLDs")
fancy_output(1, "\rFound " + str(len(tlds)) + " TLDs")

# Our pool of worker threads/processes
# signal catching is broken on OpenBSD if we use threads(ThreadPool) or processes(Pool)
# Keeping this IF stmt here as I suspect different platforms will break differently with this
if SYS_TYPE == 'linux':
  pool = multiprocessing.pool.ThreadPool(processes=args.num_threads)
elif SYS_TYPE == 'fbsd':
  pool = multiprocessing.pool.ThreadPool(processes=args.num_threads)
else:
  death('Unsupported platform' + SYS_TYPE)

# Perform IPv4 tests
if not args.no_v4:
  ipv4_addresses = [rsi.ipv4 for rsi in ROOT_SERVERS]

  if not args.no_traceroute:
    fancy_output(0, "\rRunning traceroute with " + str(args.num_threads) + " threads")
    traces = pool.starmap(trace_route, zip(itertools.repeat(find_binary('traceroute')), ipv4_addresses))
    lengths = []
    for rsi,trace in zip(ROOT_SERVERS, traces):
      dbgLog(LOG_DEBUG, "traceroute_" + rsi.name + " len:" + str(len(trace)) + " first:" + repr(trace[0]))
      lengths.append(len(trace))
      rsi.traceroute_v4 = trace

    median = str(statistics.median(lengths))
    minimum = str(min(lengths))
    maximum = str(max(lengths))
    fancy_output(5, "\rtraceroute hops min:" + minimum + " max:" + maximum + " median:" + median)

  fancy_output(0, "\rRunning IPv4 DNS queries with " + str(args.num_threads) + " threads")
  dbgLog(LOG_INFO, "Running IPv4 DNS queries with " + str(args.num_threads) + " threads")
  for ii in range(1, args.num_tests + 1):
    times_v4 = []
    if not args.no_udp:
      udp_times = pool.starmap(timed_query, [[dns.query.udp, tld, ip] for tld, ip in itertools.product(tlds, ipv4_addresses)])
      times_v4 += [time for time in udp_times if time >= 0]
      for tld in tlds:
        for rsi in ROOT_SERVERS:
            rsi.add_time_v4('udp', tld, udp_times.pop(0))

    if not args.no_tcp:
      tcp_times = pool.starmap(timed_query, [[dns.query.tcp, tld, ip] for tld, ip in itertools.product(tlds, ipv4_addresses)])
      times_v4 += [time for time in tcp_times if time >= 0]
      for tld in tlds:
        for rsi in ROOT_SERVERS:
            rsi.add_time_v4('tcp', tld, tcp_times.pop(0))

    mean = str(statistics.mean(times_v4))[:SIG_CHARS]
    minimum = str(min(times_v4))[:SIG_CHARS]
    maximum = str(max(times_v4))[:SIG_CHARS]
    fancy_output(args.delay, "\rIPv4 DNS test cycle " + str(ii) + " min:" + minimum + " max:" + maximum + " avg:" + mean)

# Perform IPv6 tests
if not args.no_v6 and IPV6_SUPPORT:
  ipv6_addresses = [rsi.ipv6 for rsi in ROOT_SERVERS]

  if not args.no_traceroute:
    fancy_output(0, "\rRunning traceroute6 with " + str(args.num_threads) + " threads")
    traces = pool.starmap(trace_route, zip(itertools.repeat(find_binary('traceroute6')), ipv6_addresses))
    lengths = []
    for rsi,trace in zip(ROOT_SERVERS, traces):
      dbgLog(LOG_DEBUG, "traceroute6_" + rsi.name + " len:" + str(len(trace)) + " first:" + repr(trace[0]))
      lengths.append(len(trace))
      rsi.traceroute_v6 = trace

    median = str(statistics.median(lengths))
    minimum = str(min(lengths))
    maximum = str(max(lengths))
    fancy_output(5, "\rtraceroute6 hops min:" + minimum + " max:" + maximum + " median:" + median)

  fancy_output(0.5, "\rRunning IPv6 DNS queries with " + str(args.num_threads) + " threads")
  dbgLog(LOG_INFO, "Running IPv6 DNS queries with " + str(args.num_threads) + " threads")
  for ii in range(1, args.num_tests + 1):
    times_v6 = []
    if not args.no_udp:
      udp_times = pool.starmap(timed_query, [[dns.query.udp, tld, ip] for tld, ip in itertools.product(tlds, ipv6_addresses)])
      times_v6 += [time for time in udp_times if time >= 0]
      for tld in tlds:
        for rsi in ROOT_SERVERS:
            rsi.add_time_v6('udp', tld, udp_times.pop(0))

    if not args.no_tcp:
      tcp_times = pool.starmap(timed_query, [[dns.query.tcp, tld, ip] for tld, ip in itertools.product(tlds, ipv6_addresses)])
      times_v6 += [time for time in tcp_times if time >= 0]
      for tld in tlds:
        for rsi in ROOT_SERVERS:
            rsi.add_time_v6('tcp', tld, tcp_times.pop(0))

    mean = str(statistics.mean(times_v6))[:SIG_CHARS]
    minimum = str(min(times_v6))[:SIG_CHARS]
    maximum = str(max(times_v6))[:SIG_CHARS]
    fancy_output(args.delay, "\rIPv6 DNS test cycle " + str(ii) + " min:" + minimum + " max:" + maximum + " avg:" + mean)

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
  except OSError:
    death("Unable to write to " + args.out_file)
else:
  print(output)

sys.exit(0)
