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
import dns.flags
import dns.message
import dns.resolver
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.query
from enum import Enum, auto
import ipaddress
import itertools
import json
import os
import multiprocessing.pool
import random
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
LOG_FNAME = 'root_perf.log'
LOG_SIZE = 1024 # Max logfile size in KB

SIG_CHARS = 7 # How many significant characters to display in fancy output
SYS_TYPE = '' # Enumerated type of system we're running on: linux, bsd, darwin, win32, cygwin
TRACEROUTE_NUM_TIMEOUTS = 5 # Number of consecutive timed out traceroute probes we tolerate before giving up
DNS_MAX_QUERIES = 5 # Number of query retries before we give up
TLDS_MAX = 100 # Max TLDs we will query
ROOT_SERVERS = [] # Our list of DNS root servers
OUTPUT = {} # Top-level dict to encode into JSON and output
DYING = False # Are we in the process of dying?

# Where we look for executable binaries
SEARCH_PATH = ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/usr/local/bin/', '/usr/local/sbin/']

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

STATIC_OPEN_RESOLVERS = [ # List of open resolvers to test
{'name': 'Cloudflare', 'a': '1.1.1.1', 'aaaa': '2606:4700:4700::1111'},
{'name': 'Google', 'a': '8.8.8.8', 'aaaa': '2001:4860:4860::8888'},
{'name': 'OpenDNS', 'a': '208.67.220.220', 'aaaa': '2620:119:35::35'},
{'name': 'Quad9', 'a': '9.9.9.9', 'aaaa': '2620:fe::9'}
]

# WHOAMI servers, RSSAC057 Section 3.4
WHOAMI_SERVERS_4 = [
{'server': 'akamai.net', 'qname': 'whoami.akamai.net', 'rr': 'A'},
{'server': 'google.com', 'qname': 'o-o.myaddr.l.google.com', 'rr': 'TXT'},
{'server': 'v4.powerdns.org', 'qname': 'whoami.v4.powerdns.org', 'rr': 'A'}
]

WHOAMI_SERVERS_6 = [
{'server': 'akamai.net', 'qname': 'whoami.akamai.net', 'rr': 'AAAA'},
{'server': 'google.com', 'qname': 'o-o.myaddr.l.google.com', 'rr': 'TXT'},
{'server': 'v6.powerdns.org', 'qname': 'whoami.v6.powerdns.org', 'rr': 'AAAA'}
]

# These correspond to the query kinds from RSSAC057 section 3.2
# https://www.icann.org/en/system/files/files/rssac-057-09sep21-en.pdf
class QKIND(Enum):
  CH = auto() # 3.2.1
  NS = auto() # 3.2.2
  DS = auto() # 3.2.3
  OPEN = auto() # Open resolvers

###########
# Classes #
###########
class Server():
  def __init__(self, name, ipv4, ipv6):
    self.name = name
    self.ipv4 = ipv4
    self.ipv6 = ipv6


class OpenResolver(Server):
  def __init__(self, name, ipv4, ipv6):
    Server.__init__(self, name, ipv4, ipv6)
    self.queries = {'ipv4': [], 'ipv6': []}

  def __repr__(self):
    return "name:" + self.name + " ipv4:" + str(self.ipv4) + " ipv6:" + str(self.ipv6) + " queries:" + repr(self.queries)

  def add_query(self, ipv, qtime):
    self.queries[ipv].append(qtime)

  # Convert this object to a dict and return it
  def to_dict(self):
    rv = {}
    rv['open_resolver'] = self.name
    rv['ipv4'] = self.ipv4
    rv['ipv6'] = self.ipv6
    rv['queries'] = self.queries
    return rv


class RootServer(Server):
  def __init__(self, name, ipv4, ipv6):
    Server.__init__(self, name, ipv4, ipv6)

    self.queries = {}
    for qkind in QKIND:
      if qkind == QKIND.OPEN:
        continue
      self.queries[qkind] = {'ipv4': {'udp':{}, 'tcp':{}}, 'ipv6':{'udp':{}, 'tcp':{}}}

    # For now we only do UDP traceroutes
    self.traceroute_v4 = []
    self.traceroute_v6 = []

  def __repr__(self): #TODO: fix
    return "name:" + self.name + " ipv4:" + str(self.ipv4) + " ipv6:" + str(self.ipv6) + " queries:" + repr(self.queriess) + \
      " trace_v4:" + repr(self.traceoute_v4) + " trace_v6:" + repr(self.traceroute_v6)

  # Add a test result for DNS query
  # TODO: Do some error checking on passed values
  def add_query(self, qkind, ipv, proto, tld, qtime, data):
    if not tld in self.queries[qkind][ipv][proto]:
      self.queries[qkind][ipv][proto][tld] = []
    entry = [qtime, data]
    self.queries[qkind][ipv][proto][tld].append(entry)

  # Convert this object to a dict and return it
  def to_dict(self):
    rv = {}
    rv['rsi'] = self.name
    rv['ipv4'] = self.ipv4
    rv['ipv6'] = self.ipv6

    rv['queries'] = {} # Convert Enum into string for output
    for qkind in QKIND:
      if qkind == QKIND.OPEN:
        continue
      rv['queries'][qkind.name] = self.queries[qkind]

    #self.anonymize_traceroutes()
    rv['traceroute_v4'] = self.traceroute_v4
    rv['traceroute_v6'] = self.traceroute_v6
    return rv

  # Anonymizes IP addresses in traceroutes
  # Currently only replaces private IP space with generic stub IP
  def anonymize_traceroutes(self):
    for ii in range(len(self.traceroute_v4)):
      self.traceroute_v4[ii] = \
        ['10.0.0.1' if ipaddress.ip_address(hop).is_private else hop for hop in self.traceroute_v4[ii]]

    for ii in range(len(self.traceroute_v6)):
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
  #      dbg_log(LOG_DEBUG, "Thread name:" + thr.name + " id:" + str(thr.ident) + " daemon:" + str(thr.daemon))

  sys.exit("SIG-" + str(signal) + " caught, exiting\n")

def death(errStr=''):
  global DYING
  DYING = True
  sys.exit("FATAL:" + errStr)

# Logs message to LOG_FNAME or tty
def dbg_log(lvl, dbgStr):
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

# Silent at LOG_ERROR
# Fancier output at LOG_WARN and LOG_INFO
# Normal output at LOG_DEBUG
# Takes a delay in seconds to wait after string(ss) is printed
def fancy_output(delay, ss):
  window = 70 # Maximum length of ss
  min_len = 2 # Minimum length of ss

  if LOG_LEVEL <= LOG_ERROR:
    return

  if LOG_LEVEL >= LOG_DEBUG:
    dbg_log(LOG_INFO, ss)
    return

  if len(ss) < min_len:
    dbg_log(LOG_ERROR, "fancy_output: output too short")
    return

  if len(ss) > window:
    dbg_log(LOG_ERROR, "fancy_output: print window exceeded")
    return

  if ss[0] != '\r':
    ss = '\r' + ss

  sys.stdout.write(ss)
  for ii in range(window - len(ss)):
    sys.stdout.write(' ')

  sys.stdout.flush()
  time.sleep(delay)

# Prints fancy_output for stats
# Takes a delay, a prefix string, and a list of numeric values
def fancy_stats(delay, prefix, vals):
  median = str(statistics.median(vals))[:SIG_CHARS]
  minimum = str(min(vals))[:SIG_CHARS]
  maximum = str(max(vals))[:SIG_CHARS]
  fancy_output(delay, "\r" + prefix + " min:" + minimum + " max:" + maximum + " median:" + median)

# Takes a string
# Returns True if it is a valid DNS label, otherwise False
def is_valid_dns_label(lab):
  if not lab.isascii():
    return False

  if not lab.replace('-', '').isalnum():
    return False

  if lab.lstrip('0123456789-') != lab:
    return False

  if len(lab) < 2 or len(lab) > 63:
    return False

  return True

# Send a single walk query and return a dnspython response message
def send_walk_query(qstr):
  if DYING:
    return None

  query = dns.message.make_query(qstr.lower(), 'NS', want_dnssec=True)
  server = str(random.choice(ROOT_SERVERS).ipv4)
  dbg_log(LOG_DEBUG, "Using server:" + server)

  try:
    rv = dns.query.udp(query, server, ignore_unexpected=True, timeout=ARGS.query_timeout)
  except dns.exception.Timeout:
    dbg_log(LOG_WARN, "send_walk_query: query timeout " + server + " qname:" + qstr)
    return None
  except dns.query.BadResponse:
    dbg_log(LOG_WARN, "send_walk_query: bad response " + server + " qname:" + qstr)
    return None
  except dns.query.UnexpectedSource:
    dbg_log(LOG_WARN, "send_walk_query: bad source IP in response " + server + " qname:" + qstr)
    return None
  except dns.exception.DNSException as e:
    dbg_log(LOG_WARN, "send_walk_query: general dns error " + server + " " + str(e))
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
        dbg_log(LOG_DEBUG, "k1:" + k1 + " k2:" + k2)
        return k1, k2
    for rr in resp.answer:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NSEC:
        k1 = rr.to_text().split()[0].rstrip('.')
        k2 = rr.to_text().split()[4].rstrip('.')
        if len(k1) == 0: # Ignore the zone apex NSEC RR
          continue
        dbg_log(LOG_DEBUG, "k1:" + k1 + " k2:" + k2)
        return k1, k2

  elif resp.rcode() == 0 and resp.opcode() == 0: # NOERROR
    for rr in resp.authority:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NS:
        ns = rr.to_text().split()[0].rstrip('.')
        dbg_log(LOG_DEBUG, "ns:" + ns)
        return ns, ns
    for rr in resp.answer:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NS:
        ns = rr.to_text().split()[0].rstrip('.')
        dbg_log(LOG_DEBUG, "ns:" + ns)
        return ns, ns

  else: # Need to handle SERVFAIL
    dbg_log(LOG_WARN, "handle_walk_response unhandled response:" + str(resp))

  return None, None

# Iteratively find X tlds surrounding qstr
# Returns list of X tlds alpha sorted
def find_tlds(qstr, x):
  dbg_log(LOG_DEBUG, "find_tlds:" + qstr + " x:" + str(x))
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
     dbg_log(LOG_DEBUG, "find_tlds_while DNS query failed " + str(DNS_MAX_QUERIES) + " times")
     death("Max query attempts exceeded")

    dbg_log(LOG_DEBUG, "find_tlds_while dn_down:" + dn_down + " dn_up:" + dn_up + " len_tlds:" + str(len(tlds)))
    if len(tlds) >= x or not going_down and not going_up:
      return sorted(tlds)[:x]

    if going_down:
      resp = send_walk_query(dn_down)
      if resp == None:
        dbg_log(LOG_WARN, "find_tlds walk_down query failed for " + qstr)
        query_attempts += 1
        continue
      else:
        query_attempts = 0
        dn_down, _ = handle_walk_response(resp)
      if dn_down == None:
        dbg_log(LOG_DEBUG, "find_tlds finished walking down")
        going_down = False
        dn_down = '.'
      else:
        if len(dn_down) > 0:
          tlds[dn_down] = True
        dn_down = dn_dec(dn_down)

    if going_up:
      resp = send_walk_query(dn_up)
      if resp == None:
        dbg_log(LOG_WARN, "find_tlds walk_up query failed for " + qstr)
        query_attempts += 1
        continue
      else:
        query_attempts = 0
        _, dn_up = handle_walk_response(resp)
      if dn_up == None:
        dbg_log(LOG_DEBUG, "find_tlds finished walking up")
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
# Takes a string protocol for the type of query(TCP/UDP), a TLD to query, an IP address as string, and a QKIND
# Returns time and resultant data
# On failure returns -1 and string description of failure
def timed_query(proto, tld, ip, qkind):
  if DYING:
    return -1, 'process dying'

  if qkind is QKIND.CH:
    query = dns.message.make_query('hostname.bind', 'TXT', rdclass=dns.rdataclass.CH, use_edns=False)
    proto = 'udp'
  elif qkind is QKIND.NS:
    query = dns.message.make_query(tld, 'NS', rdclass=dns.rdataclass.IN, flags=dns.flags.CD, use_edns=True)
  elif qkind is QKIND.DS:
    query = dns.message.make_query(tld, 'DS', rdclass=dns.rdataclass.IN, flags=dns.flags.CD, ednsflags=0, use_edns=True)
  elif qkind is QKIND.OPEN:
    query = dns.message.make_query('.', 'NS', rdclass=dns.rdataclass.IN, use_edns=False)
  else:
    dbg_log(LOG_ERROR, "timed_query:" + proto + " invalid query kind")
    return -1, 'invalid query kind'

  if proto.lower() == 'tcp':
    qtime, resp = tcp_timed_query(query, ip)
  else:
    qtime, resp = udp_timed_query(query, ip)

  if not isinstance(resp, dns.message.Message):
    return qtime, resp
  if resp.rcode() != 0:
    return qtime, 'bad_rcode:' + dns.rcode.to_text(response.rcode())
  if qkind is QKIND.OPEN:
    return qtime, ''

  if qkind is QKIND.CH:
    rrset = resp.get_rrset(dns.message.ANSWER, dns.name.from_text('hostname.bind'), dns.rdataclass.CH, dns.rdatatype.TXT)
  elif qkind is QKIND.NS:
    rrset = resp.get_rrset(dns.message.AUTHORITY, dns.name.from_text(tld), dns.rdataclass.IN, dns.rdatatype.NS)
  elif qkind is QKIND.DS:
    rrset = resp.get_rrset(dns.message.ANSWER, dns.name.from_text(tld), dns.rdataclass.IN, dns.rdatatype.DS)

  if rrset == None:
    dbg_log(LOG_WARN, "timed_query:" + proto + ":" + qkind.name + " no_data")
    return qtime, 'no_data'
  else:
    dbg_log(LOG_DEBUG, qkind.name + ": rrs:" + str(len(rrset)) + " : " + rrset[0].to_text())
    return qtime, '|'.join([rr.to_text() for rr in rrset]).strip("\"")

# Perform timed query over TCP
# Takes a dns.message.query and an IP
# Returns time and string data or error message
# On failure returns -1 and string description of failure
def tcp_timed_query(query, ip):
  try:
    if ipaddress.ip_address(ip).version == 4:
      sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    else:
      sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)

    sock.connect((ip, 53))
    start_time = time.monotonic()
    response = dns.query.tcp(query, '', timeout=ARGS.query_timeout, sock=sock)

  except dns.exception.Timeout:
    dbg_log(LOG_WARN, "tcp_timed_query:query_timeout: ip:" + ip)
    sock.close()
    return -1, 'query_timeout'
  except dns.query.BadResponse:
    dbg_log(LOG_WARN, "tcp_timed_query:bad_response: ip:" + ip)
    sock.close()
    return -1, 'bad_response'
  except dns.query.UnexpectedSource:
    dbg_log(LOG_WARN, "tcp_timed_query:bad_source: ip:" + ip)
    sock.close()
    return -1, 'bad_source'
  except dns.exception.DNSException as e:
    dbg_log(LOG_WARN, "tcp_timed_query:dns_exception: ip:" + ip + ":" + str(e))
    sock.close()
    return -1, 'dns_exception'
  except ConnectionError as e:
    dbg_log(LOG_WARN, "tcp_timed_query:connection_error: ip:" + ip + ":" + str(e))
    sock.close()
    return -1, 'connection_error'
  except EOFError as e:
    dbg_log(LOG_WARN, "tcp_timed_query:eof_err: ip:" + ip + ":" + str(e))
    sock.close()
    return -1, 'eof_error'
  except OSError as e:
    dbg_log(LOG_WARN, "tcp_timed_query:os_err: ip:" + ip + ":" + str(e))
    sock.close()
    return -1, 'os_error'

  sock.close()
  qtime = time.monotonic() - start_time
  dbg_log(LOG_DEBUG, "tcp_timed_query: ip:" + ip + ":" + str(qtime))
  return qtime, response

# Perform timed query over UDP
# Takes a dns.message.query and an IP
# Returns time and string data or error message
# On failure returns -1 and string description of failure
def udp_timed_query(query, ip):
  start_time = time.monotonic()

  try:
    start_time = time.monotonic()
    response = dns.query.udp(query, ip, timeout=ARGS.query_timeout)
  except dns.exception.Timeout:
    dbg_log(LOG_WARN, "udp_timed_query:query_timeout: ip:" + ip)
    return -1, 'query_timeout'
  except dns.query.BadResponse:
    dbg_log(LOG_WARN, "udp_timed_query:bad_response: ip:" + ip)
    return -1, 'bad_response'
  except dns.query.UnexpectedSource:
    dbg_log(LOG_WARN, "udp_timed_query:bad_source: ip:" + ip)
    return -1, 'bad_source'
  except dns.exception.DNSException as e:
    dbg_log(LOG_WARN, "udp_timed_query:dns_exception: ip:" + ip + ":" + str(e))
    return -1, 'dns_exception'
  except ConnectionError as e:
    dbg_log(LOG_WARN, "udp_timed_query:connection_err: ip:" + ip + ":" + str(e))
    return -1, 'connection_error'
  except OSError as e:
    dbg_log(LOG_WARN, "udp_timed_query:os_error: ip:" + ip + ":" + str(e))
    return -1, 'os_error'

  qtime = time.monotonic() - start_time
  dbg_log(LOG_DEBUG, "udp_timed_query: ip:" + ip + ":" + str(qtime))
  return qtime, response

# Performs the complete DNS test cycle and stores the results
# Takes a list of TLDs and a list of IPv4 addresses
# Returns a list of float times
# QKIND.OPEN queries are not included in returned times
def dns_test_cycle(tlds, ip_addresses):
  rv = []
  protos = []
  if not ARGS.no_udp:
    protos.append('udp')
  if not ARGS.no_tcp:
    protos.append('tcp')

  for qkind in QKIND:
    if qkind == QKIND.OPEN:
      results = POOL.starmap(timed_query, [['udp', '.', ip, qkind] for ip in ip_addresses])
      for res in OPEN_RESOLVERS:
        qtime, data = results.pop(0)
        if ipaddress.ip_address(ip_addresses[0]).version == 4:
          res.add_query('ipv4', qtime)
        else:
          res.add_query('ipv6', qtime)

    elif qkind == QKIND.CH:
      for proto in protos:
        results = POOL.starmap(timed_query, [[proto, '.', ip, qkind] for ip in ip_addresses])
        rv += [res[0] for res in results if res[0] >= 0]
        for rsi in ROOT_SERVERS:
          qtime, data = results.pop(0)
          if ipaddress.ip_address(ip_addresses[0]).version == 4:
            rsi.add_query(qkind, 'ipv4', proto, '.', qtime, data)
          else:
            rsi.add_query(qkind, 'ipv6', proto, '.', qtime, data)

    else:
      for proto in protos:
        results = POOL.starmap(timed_query, [[proto, tld, ip, qkind] for tld, ip in itertools.product(tlds, ip_addresses)])
        rv += [res[0] for res in results if res[0] >= 0]
        for tld in tlds: # Is this wrong for CH?
          for rsi in ROOT_SERVERS:
            qtime, data = results.pop(0)
            if ipaddress.ip_address(ip_addresses[0]).version == 4:
              rsi.add_query(qkind, 'ipv4', proto, tld, qtime, data)
            else:
              rsi.add_query(qkind, 'ipv6', proto, tld, qtime, data)

  return rv

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
  time.sleep(random.uniform(1, ARGS.num_threads))

  rv = []
  cmd = binary + " -n -p 53 -m 32 " + str(ip)
  dbg_log(LOG_INFO, "trace_route:" + cmd)
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
    dbg_log(LOG_ERROR, "trace_route subprocess TimeoutExpired" + str(e))
    return rv
  except subprocess.CalledProcessError as e:
    dbg_log(LOG_ERROR, "trace_route subprocess CallProcessError" + str(e))
    return rv
  except OSError as e:
    dbg_log(LOG_ERROR, "trace_route subprocess OSError" + str(e))
    return rv
  except subprocess.SubprocessError:
    dbg_log(LOG_ERROR, "trace_route general subprocess error")
    return rv

# Returns list of RSIs if possible, otherwise returns None
# Uses locally configured resolver
def local_discover_root_servers():
  try:
    d = dns.resolver.Resolver()
  except dns.exception.DNSException as e:
    dbg_log(LOG_WARN, "local_discover_root_servers: Local resolver not found " + repr(e))
    return None

  try:
    resp = d.resolve('.', 'NS', search=True) # TODO: Should 'search' really be True here?
  except dns.exception.DNSException as e:
    dbg_log(LOG_WARN, "local_discover_root_servers: Failed to query local resolver for . " + repr(e))
    return None

  names = [str(name).strip('.').lower() for name in resp.rrset]

  rv = []
  for name in sorted(names):
    try:
      resp_a = d.resolve(name, 'A', search=True)
    except dns.exception.DNSException as e:
      dbg_log(LOG_WARN, "local_discover_root_servers: Failed querying A record for " + name + " " + repr(e))
      return None

    try:
      resp_aaaa = d.resolve(name, 'AAAA', search=True)
    except dns.exception.DNSException as e:
      dbg_log(LOG_WARN, "local_discover_root_servers: Failed querying AAAA record for " + name + " " + repr(e))
      return None

    rv.append(RootServer(name, str(resp_a.rrset[0]), str(resp_aaaa.rrset[0])))

  return rv

# Returns list of RSIs if possible, otherwise returns None
# Uses STATIC_SERVERS to find all servers
# Takes a function to use for querying(udp or tcp)
# TODO: Get working with IPv6
def auth_discover_root_servers(fn):
  random.shuffle(STATIC_SERVERS)

  # Because 'reasons' we may not get the full priming response in one query
  # So we construct it from multiple queries just to be sure
  discovered = []
  for server in STATIC_SERVERS:
    query = dns.message.make_query('.', 'NS')
    dest = server['a']
    dbg_log(LOG_DEBUG, "auth_discover_root_servers: Trying destination:" + dest)

    try:
      primer = fn(query, dest, timeout=ARGS.query_timeout)
      dbg_log(LOG_DEBUG, repr(primer.section_from_number(3)))
    except dns.exception.Timeout:
      dbg_log(LOG_WARN, "auth_discover_root_servers: query timeout " + dest)
      continue
    except dns.query.BadResponse:
      dbg_log(LOG_WARN, "auth_discover_root_servers: bad response " + dest)
      continue
    except dns.query.UnexpectedSource:
      dbg_log(LOG_WARN, "auth_discover_root_servers: bad source IP in response " + dest)
      continue
    except dns.exception.DNSException as e:
      dbg_log(LOG_WARN, "auth_discover_root_servers: general dns error " + dest + " " + str(e))
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

# Makes queries to WHOAMI servers and determines our external IPv4 and IPv6 addresses
# Returns a tuple of strings (IPv4_address, IPv6_address)
def discover_whoami():
  def get_ip(ver): # Perform all the DNS queries and return a string
    if ver == 4:
      whoami_servers = WHOAMI_SERVERS_4
    else:
      whoami_servers = WHOAMI_SERVERS_6

    for entry in whoami_servers:
      try:
        resp_ns = stub.resolve(entry['server'], 'NS', search=False)
      except:
        continue

      for ns in resp_ns.rrset:
        try:
          if ver == 4:
            resp_ip = stub.resolve(ns.to_text(), 'A', search=False)
          else:
            resp_ip = stub.resolve(ns.to_text(), 'AAAA', search=False)
        except:
          continue

        for ip in resp_ip.rrset:
          auth_query = dns.message.make_query(entry['qname'], entry['rr'])
          try:
            auth_resp = dns.query.udp(auth_query, ip.to_text(), timeout=ARGS.query_timeout)
          except:
            continue

          if auth_resp.rcode() != 0:
            continue

          ip_address = auth_resp.answer[0].to_text().split(' ')[-1].strip("\"")
          if ver == 4:
            try:
              if ipaddress.ip_address(ip_address).version == 4:
                return ip_address
            except:
              continue
          else:
            try:
              if ipaddress.ip_address(ip_address).version == 6:
                return ip_address
            except:
              continue

    return ''

  try:
    stub = dns.resolver.Resolver()
  except:
    dbg_log(LOG_ERROR, "determine_whoami: Local resolver not found")
    return 'determine_whoami: Local resolver not found'

  ipv4 = ipv6 = ''
  if not ARGS.no_v4:
    ipv4 = get_ip(4)
  if not ARGS.no_v6 and IPV6_SUPPORT:
    ipv6 = get_ip(6)
  return ipv4, ipv6

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
    for directory in SEARCH_PATH:
      if test(directory + fn):
        return directory + fn
    return None

  death('Unsupported platform ' + SYS_TYPE)

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
args_epilog = "If --out-file is not specified stdout is used. \
UDP port 53 is used for traceroute probes."

ap = argparse.ArgumentParser(description = 'Test DNS Root Servers',
                               formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                               epilog = args_epilog)
ap.add_argument('-d', '--delay', type=float, action='store', default=0.05,
                  dest='delay', help='Delay between each test cycle in seconds')
ap.add_argument('-n', '--num-tests', type=int, action='store', default=10,
                  dest='num_tests', help='Number of test cycles per-TLD')
ap.add_argument('-o', '--out-file', type=str, action='store', default='',
                  dest='out_file', help='Filename for output')
ap.add_argument('-q', '--query-timeout', type=int, action='store', default=10,
                  dest='query_timeout', help='DNS query timeout in seconds')
ap.add_argument('-t', '--tlds', type=str, action='store', default='com',
                  dest='tlds', help='Comma separated list of TLDs to query, or number between 1 and ' + str(TLDS_MAX) + ' for random TLDs')
ap.add_argument('-v', '--verbose', action='count', default=0,
                  dest='verbose', help='Verbose output, repeat for increased verbosity')

ap.add_argument('--threads', type=int, action='store', default=6, choices=[1,2,3,4,5,6],
                  dest='num_threads', help='Number of threads to run concurrently')

ap.add_argument('--no-tcp', action='store_true', default=False,
                  dest='no_tcp', help='Turn off TCP testing')
ap.add_argument('--no-udp', action='store_true', default=False,
                  dest='no_udp', help='Turn off UDP testing')

ap.add_argument('--no-ipv4', action='store_true', default=False,
                  dest='no_v4', help='Turn off IPv4 testing')
ap.add_argument('--no-ipv6', action='store_true', default=False,
                  dest='no_v6', help='Turn off IPv6 testing')

ap.add_argument('--no-traceroute', action='store_true', default=False,
                  dest='no_traceroute', help='Turn off IPv4 and IPv6 traceroute')

ARGS = ap.parse_args()

LOG_LEVEL = min(ARGS.verbose, LOG_DEBUG)
fancy_output(0, "\rBegin Execution")
random.seed()

if ARGS.no_v4 and ARGS.no_v6:
  death("Both IPv4 and IPv6 disabled")

if ARGS.no_udp and ARGS.no_tcp:
  death("Both TCP and UDP disabled")

SYS_TYPE = get_sys_type() # Determine what the OS is
dbg_log(LOG_INFO, "SYS_TYPE:" + SYS_TYPE)
OUTPUT['sys_type'] = SYS_TYPE

# Find our root servers
ROOT_SERVERS = local_discover_root_servers()
if not ROOT_SERVERS:
  dbg_log(LOG_WARN, "Local resolution of root servers failed, attempting direct resolution via TCP.")
  ROOT_SERVERS = auth_discover_root_servers(dns.query.tcp)
if not ROOT_SERVERS:
  dbg_log(LOG_WARN, "Direct TCP queries to root servers failed, attempting direct resolution via UDP.")
  ROOT_SERVERS = auth_discover_root_servers(dns.query.udp)
if not ROOT_SERVERS:
  death("Unable to contact any root servers")
fancy_output(1, "\rFound " + str(len(ROOT_SERVERS)) + " root servers")

# Init our open resolvers
OPEN_RESOLVERS = [OpenResolver(res['name'], res['a'], res['aaaa']) for res in STATIC_OPEN_RESOLVERS]
fancy_output(1, "\rUsing " + str(len(OPEN_RESOLVERS)) + " open resolvers")

# Is IPv6 supported on this host?
if not ARGS.no_v6:
  IPV6_SUPPORT = True
  try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect( (str(random.choice(ROOT_SERVERS).ipv6), 53) )
    s.close()
  except OSError:
    dbg_log(LOG_INFO, "No local IPv6 configured")
    IPV6_SUPPORT = False

if ARGS.no_v4 and not IPV6_SUPPORT:
  death("IPv4 disabled and IPv6 not configured")

# Die if user requested traceroute and binaries cannot be found
if not ARGS.no_traceroute:
  if not ARGS.no_v4 and not find_binary('traceroute'):
    dbg_log(LOG_DEBUG, "No traceroute binary found in " + repr(SEARCH_PATH))
    death("IPv4 traceroute requested but traceroute binary not found, try running with --no-traceroute option")
  if not ARGS.no_v6 and not find_binary('traceroute6'):
    dbg_log(LOG_DEBUG, "No traceroute6 binary found in " + repr(SEARCH_PATH))
    death("IPv6 traceroute requested but traceroute6 binary not found, try running with --no-traceroute option")

# Make our list of TLDs
if not ARGS.tlds.isascii():
  death("Invalid --tlds argument")
if ARGS.tlds.isdecimal():
  if int(ARGS.tlds) < 1 or int(ARGS.tlds) > TLDS_MAX:
    death("--tlds out of bounds")
  else:
    # This ranges from 'aa' to 'zz'
    tlds = find_tlds(chr(random.randint(97, 122)) + chr(random.randint(97, 122)), int(ARGS.tlds))
else:
  tlds = ARGS.tlds.replace('.', '').lower().split(',')
  if not all(map(is_valid_dns_label, tlds)):
    death("--tlds contains invalid TLD")
fancy_output(1, "\rFound " + str(len(tlds)) + " TLDs")

# Our global pool of worker threads/processes
# signal catching is broken on OpenBSD if we use threads(ThreadPool) or processes(Pool)
# Keeping this IF stmt here as I suspect different platforms will break differently with this
if SYS_TYPE == 'linux':
  POOL = multiprocessing.pool.ThreadPool(processes=ARGS.num_threads)
elif SYS_TYPE == 'fbsd':
  POOL = multiprocessing.pool.ThreadPool(processes=ARGS.num_threads)
else:
  death('Unsupported platform' + SYS_TYPE)

# Discover our external IP addresses
OUTPUT['external_ipv4'], OUTPUT['external_ipv6'] = discover_whoami()
fancy_output(1, "\rDiscovered external IPs " + OUTPUT['external_ipv4'] + " " + OUTPUT['external_ipv6'])

OUTPUT['timestamps'] = {}
OUTPUT['timestamps']['start'] = datetime.datetime.utcnow().isoformat('T', timespec='seconds') + 'Z'

# Perform IPv4 tests
if not ARGS.no_v4:
  ipv4_addresses = [rsi.ipv4 for rsi in ROOT_SERVERS]

  if not ARGS.no_traceroute:
    fancy_output(0, "\rRunning traceroute with " + str(ARGS.num_threads) + " threads")
    traces = POOL.starmap(trace_route, zip(itertools.repeat(find_binary('traceroute')), ipv4_addresses))
    lengths = []
    for rsi,trace in zip(ROOT_SERVERS, traces):
      dbg_log(LOG_DEBUG, "traceroute_" + rsi.name + " len:" + str(len(trace)) + " first:" + repr(trace[0]))
      lengths.append(len(trace))
      rsi.traceroute_v4 = trace
    fancy_stats(5, "\rtraceroute hops ", lengths)

  fancy_output(0, "\rQuerying on IPv4 with " + str(ARGS.num_threads) + " threads")
  for ii in range(1, ARGS.num_tests + 1):
    fancy_stats(ARGS.delay, "\rRSI IPv4 query times cycle:" + str(ii),
                  dns_test_cycle(tlds, ipv4_addresses))

# Perform IPv6 tests
if not ARGS.no_v6 and IPV6_SUPPORT:
  ipv6_addresses = [rsi.ipv6 for rsi in ROOT_SERVERS]

  if not ARGS.no_traceroute:
    fancy_output(0, "\rRunning traceroute6 with " + str(ARGS.num_threads) + " threads")
    traces = POOL.starmap(trace_route, zip(itertools.repeat(find_binary('traceroute6')), ipv6_addresses))
    lengths = []
    for rsi,trace in zip(ROOT_SERVERS, traces):
      dbg_log(LOG_DEBUG, "traceroute6_" + rsi.name + " len:" + str(len(trace)) + " first:" + repr(trace[0]))
      lengths.append(len(trace))
      rsi.traceroute_v6 = trace
    fancy_stats(5, "\rtraceroute6 hops ", lengths)

  fancy_output(0.5, "\rQuerying on IPv6 with " + str(ARGS.num_threads) + " threads")
  for ii in range(1, ARGS.num_tests + 1):
    fancy_stats(ARGS.delay, "\rRSI IPv6 query times cycle:" + str(ii),
                  dns_test_cycle(tlds, ipv6_addresses))

OUTPUT['timestamps']['end'] = datetime.datetime.utcnow().isoformat('T', timespec='seconds') + 'Z'
POOL.close()
fancy_output(0, "\rFinished testing")
print()

# Create output and write it
OUTPUT['RSIs'] = [rsi.to_dict() for rsi in ROOT_SERVERS]
OUTPUT['open_resolvers'] = [res.to_dict() for res in OPEN_RESOLVERS]
out_str = json.dumps(OUTPUT, indent=2)

if len(ARGS.out_file) > 0:
  try:
    fh = open(ARGS.out_file, 'w')
    fh.write(out_str)
    fh.close()
  except OSError:
    death("Unable to write to " + ARGS.out_file)
else:
  print(out_str)

sys.exit(0)
