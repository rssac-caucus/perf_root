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

import sys
import os
import datetime
import signal
import dns.resolver
import dns.query
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import threading
import hashlib
import subprocess as subp
import re
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
#sys.setrecursionlimit(1000)

###########
# Classes #
###########

####################
# GLOBAL FUNCTIONS #
####################

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

def find_nsec(qstr):
  global tlds
  dbgLog(LOG_DEBUG, "find_nsec:" + qstr + " len_tlds:" + str(len(tlds)))
  query = dns.message.make_query(qstr.lower(), 'NS', want_dnssec=True)
  resp = dns.query.udp(query, '192.168.1.1', ignore_unexpected=True)
  #print(str(resp))

  if resp.rcode() == 3 and resp.opcode() == 0: # NXDOMAIN response
  #print(repr(resp.authority))
    for rr in resp.authority:
      if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.NSEC:
        k1 = rr.to_text().split()[0].rstrip('.')
        k2 = rr.to_text().split()[4].rstrip('.')
        if len(k1) > 0 and k1 not in tlds:
          dbgLog(LOG_DEBUG, "k1:" + k1)
          tlds[k1] = True
          find_nsec(dn_inc(k1))
          find_nsec(dn_dec(k1))
        if len(k2) > 0 and k2 not in tlds:
          dbgLog(LOG_DEBUG, "k2:" + k2)
          tlds[k2] = True
          find_nsec(dn_inc(k2))
          find_nsec(dn_dec(k2))
  else:
    pass # We need to handle the case where we don't get an NSEC RRSET back, but instead get a valid NS RRSET

# Increment a domain name for walking
def dn_inc(dn):
  if ord(dn[-1:]) == 122: # lowercase 'z'
    if len(dn) < 62: # Maximum DNS label length == 63
      if len(dn) == 1:
        return dn + 'a'
      else:
        return dn_inc(dn[:-1]) + 'z'
    else:
      return dn
  else:
    return dn[:len(dn)-1] + chr(ord(dn[-1:]) + 1)

# This is broken
# Decrement a domain name for walking
def dn_dec(dn):
  dbgLog(LOG_DEBUG, "dn_dec:" + dn)
  if ord(dn[-1:]) == 97: # lowercase 'a'
    if len(dn) == 1: # We can't return a zero-length string
      return dn
    else:
      return dn_dec(dn[:-1]) + 'a'
  else:
    return dn[:len(dn)-1] + chr(ord(dn[-1:]) - 1)

    
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

tlds = {}

find_nsec('verge')
print(repr(sorted(tlds)))
print("tlds_len:" + str(len(tlds)))
        

