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
import json
import os
import random
#import re
#import signal
#import subprocess
import sys
import time

#####################
# DEFAULT CONSTANTS #
#####################
# Logging constants
LOG_ERROR = 1
LOG_WARN = 2
LOG_INFO = 3
LOG_DEBUG = 4
LOG_LEVEL = LOG_DEBUG
LOG_OUTPUT = 'tty' # 'tty' | 'file' | False
LOG_FNAME = 'perf_root.log'
LOG_SIZE = 1024 # Max logfile size in KB

QUERY_TIMEOUT = 30 # seconds before timing out a DNS query
NUM_TLDS = 10 # How many tlds to find via walking
ROOT_SERVERS = {} # A dictionary of RootServer objects
NUM_TESTS = 2 # How many timed queries to perform, for each TLD, for each root server

###########
# Classes #
###########
class RootServer:
  def __init__(self):
    self.ipv4 = ''
    self.ipv6 = ''
    self.times_v4 = {}
    self.times_v6 = {}

  def __repr__(self):
    return "ipv4:" + str(self.ipv4) + " ipv6:" + str(self.ipv6) + " times_v4:" + repr(self.times_v4) + " times_v6:" + repr(self.times_v6)

  def add_time_v4(self, tld, time):
    if not tld in self.times_v4:
      self.times_v4[tld] = [time]
    else:
      self.times_v4[tld].append(time)

  def add_time_v6(self, tld, time):
    if not tld in self.times_v6:
      self.times_v6[tld] = [time]
    else:
      self.times_v6[tld].append(time)

  # Convert this object to YAML and return it
  def to_json(self):
    return json.dumps(self.times_v4) + "\n" + json.dumps(self.times_v6)

####################
# GLOBAL FUNCTIONS #
####################
def death(errStr=''):
  print("FATAL:" + errStr)
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

# Send a single walk query and return a dnspython response message
def send_walk_query(qstr):
  query = dns.message.make_query(qstr.lower(), 'NS', want_dnssec=True)

  server = str(ROOT_SERVERS[random.choice(list(ROOT_SERVERS))].ipv4)
  dbgLog(LOG_DEBUG, "Using server:" + server)

  try:
    rv = dns.query.udp(query, server, ignore_unexpected=True, timeout=QUERY_TIMEOUT)
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
    death("FATAL: First DNS query failed " + qstr)

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

def parse_root_hints(root_hints='named.cache'):
  rv = {}
  fn = open(root_hints, 'r')
  for line in fn:
    if line[0] != ';' and line[0] != '.':
      rsi = line.split()[0].rstrip('.')
      if not rsi in rv:
        rv[rsi] = RootServer()

      ip = ipaddress.ip_address(line.split()[3])
      if ip.version == 4:
        rv[rsi].ipv4 = ip
      elif ip.version == 6:
        rv[rsi].ipv6 = ip

  fn.close()
  return rv

# Time the query and response to a root server IPv4 address
# Returns time in seconds as float for the query and -1 on failure
def timed_query_v4(tld, ip):
  query = dns.message.make_query(tld, 'NS')

  start_time = time.perf_counter()
  try:
    dns.query.udp(query, str(ip), ignore_unexpected=True, timeout=QUERY_TIMEOUT)
  except dns.exception.Timeout:
    dbgLog(LOG_ERROR, "timed_query_v4: query timeout " + tld)
    return -1
  except dns.query.BadResponse:
    dbgLog(LOG_ERROR, "timed_query_v4: bad response " + tld)
    return -1

  dbgLog(LOG_DEBUG, "timed_query_v4 time: " + str(time.perf_counter() - start_time))
  return time.perf_counter() - start_time

###################
# BEGIN EXECUTION #
###################
# Enable debugging
if LOG_OUTPUT == 'file':
  try:
    LOG_HANDLE = open(LOG_FNAME, 'w', 1)
  except:
    death("Unable to open debug log file")

dbgLog(LOG_DEBUG, "Begin Execution")
random.seed()

ROOT_SERVERS = parse_root_hints()

# This ranges from 'aa' to 'zz'
tlds = find_tlds(chr(random.randint(97, 122)) + chr(random.randint(97, 122)), NUM_TLDS)
#print(find_tlds('uk', NUM_TLDS))

for ii in range(1, NUM_TESTS + 1):
  dbgLog(LOG_DEBUG, "Begin test round " + str(ii))
  for rsi in ROOT_SERVERS:
    for tld in tlds:
      ROOT_SERVERS[rsi].add_time_v4(tld, timed_query_v4(tld, ROOT_SERVERS[rsi].ipv4))

#print(repr(ROOT_SERVERS))

for rsi in ROOT_SERVERS:
  print(ROOT_SERVERS[rsi].to_json())
