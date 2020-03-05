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
import hashlib
import os
import random
import re
import signal
import subprocess
import sys
import threading
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

QUERY_TIMEOUT = 30 # seconds before timing out
NUM_TLDS = 2000 # How many tlds to find via walking, zero for all of them
DNS_SERVER = '192.168.1.1' # We'll need to get fancier eventually

###########
# Classes #
###########

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
  #ts = dt.strftime("%b %d %H:%M:%S.%f")
  ts = dt.strftime("%H:%M:%S.%f")
  outStr = ts + "> " + logPrefix[lvl] + "> " + dbgStr

  if LOG_LEVEL == LOG_DEBUG:
    outStr += "> "
    for thr in threading.enumerate():
      outStr += thr.name + " "
    outStr.rstrip("")

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

# Send a single query and return a dnspython response
def send_query(qstr):
  query = dns.message.make_query(qstr.lower(), 'NS', want_dnssec=True)

  try:
    rv = dns.query.udp(query, DNS_SERVER, ignore_unexpected=True, timeout=QUERY_TIMEOUT)
  except dns.exception.Timeout:
    dbgLog(LOG_ERROR, "send_query: query timeout " + qstr)
    return None
  except dns.query.BadResponse:
    dbgLog(LOG_ERROR, "send_query: bad response " + qstr)
    return None

  return rv

# Process the response from a DNS query
# Return the two adjacent domain names for NXDOMAIN
# Return the same name twice for NOERROR
# Return None None for everything else, including when we get to the end of the zone
def handle_response(resp):
  if resp.rcode() == 3 and resp.opcode() == 0: # NXDOMAIN
    for rr in resp.authority:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NSEC:
        k1 = rr.to_text().split()[0].rstrip('.')
        k2 = rr.to_text().split()[4].rstrip('.')
        if len(k1) == 0: # Ignore the zone apex NSEC RR
          continue
        dbgLog(LOG_DEBUG, "k1:" + k1 + " k2:" + k2)
        return k1, k2
  elif resp.rcode() == 0 and resp.opcode() == 0: # NOERROR
    for rr in resp.answer:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NS:
        ns = rr.to_text().split()[0].rstrip('.')
        dbgLog(LOG_DEBUG, "ns:" + ns)
        return ns, ns
  else: # Need to handle SERVFAIL 
    dbgLog(LOG_WARN, "handle_response unhandled response:" + str(resp))

  return None, None

# Iteratively find X tlds surrounding qstr
def find_tlds(qstr, x):
  dbgLog(LOG_DEBUG, "find_tlds:" + qstr + " x:" + str(x))
  tlds = {}

  # The first time is special
  resp = send_query(qstr)
  if not resp:
    death("FATAL: First DNS query failed " + qstr)

  dn_down, dn_up = handle_response(resp)
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
      resp = send_query(dn_down)
      if resp == None:
        dbgLog(LOG_WARN, "find_tlds walk_down query failed for " + qstr)
      dn_down, junk = handle_response(resp)
      if dn_down == None:
        dbgLog(LOG_DEBUG, "find_tlds finished walking down")
        going_down = False
        dn_down = '.'
      else:
        if len(dn_down) > 0:
          tlds[dn_down] = True
        dn_down = dn_dec(dn_down)

    if going_up:
      resp = send_query(dn_up)
      if resp == None:
        dbgLog(LOG_WARN, "find_tlds walk_up query failed for " + qstr)
      junk, dn_up = handle_response(resp)
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

# This ranges from 'aa' to 'zz'
print(find_tlds(chr(random.randint(97, 122)) + chr(random.randint(97, 122)), NUM_TLDS))

