#!/usr/bin/env python

""" 
Parses thrasher log to watch for activity.  
Interact with iptables upon detected actions.
"""

import commands
import os
import re
import sys
import time
from optparse import OptionParser
import warnings

__version__ = 0.1


blob = """Nov 18 18:53:21 46.21151.170 thrashd-PMPAuth_MTC: holding down address 64.180.110.186 triggered by 46.21188.76
Nov 18 18:53:21 46.21151.170 thrashd-IdP: holding down address 114.36.191.204 triggered by 46.2178.170
Nov 18 18:53:25 46.21151.170 thrashd-PMPAuth_MTC: holding down address 99.18.136.33 triggered by 46.21151.174
Nov 18 18:53:26 188.205.185.131 thrashd-Search: holding down address 165.155.192.70 triggered by 188.205.202.18
Nov 18 18:53:27 46.21151.170 thrashd-IdP: holding down address 118.161.147.10 triggered by 46.2178.168
Nov 18 18:53:27 46.21151.170 thrashd-PMPAuth_MTC: holding down address 217.194.66.146 triggered by 188.205.137.82
Nov 18 18:53:30 63.10.213.37 thrashd-Sink1: expired address 172.163.47.66"""
log = blob.splitlines()

log_re = re.compile(r'^(?P<timestamp>\w{3} \d\d \d\d:\d\d:\d\d) (?P<loghost>\d+\.\d+\.\d+\.\d+) (?P<instance>\S+): (?P<action>holding down|expired) address (?P<attacker>\d+\.\d+\.\d+\.\d+)\s?(?:triggered by (?P<trigger>\d+\.\d+\.\d+\.\d+))?') 

ACTIONS = {
    'holding down': 'I', # I = insert
    'expired': 'D',      # D = delete
}

class IPTablesWarning(Warning): 
    pass

def iptables_interact(parts):
    """
    ## add
    cmd = "iptables -% INPUT -s %s -j DROP" % parts['attacker']

    ## del
    cmd = "iptables -D INPUT -s %s -j DROP" % parts['attacker']
    """
    p = parts

    ## execute
    cmd = "iptables -%s INPUT -s %s -j DROP" % (ACTIONS[p['action']], p['attacker'])
    #status, output = commands.getstatusoutput(cmd)
    #if status > 0:
    #    warnings.warn('Problem interacting with iptables for %s' % p['attacker'], IPTablesWarning)
    print cmd

def handle_line(line):
    print line,
    line_parts = log_re.match(line).groupdict()
    action     = line_parts['action']

    iptables_interact(line_parts)

def tail_lines(fd, linesback=10):
    """
    Snagged from Python Cookbook
    """
    avgcharsperline = 75

    while 1:
        try:
            fd.seek(-1 * avgcharsperline * linesback, 2)
        except IOError:
            fd.seek(0)

        if fd.tell() == 0:
            atstart = 1
        else:
            atstart = 0

        lines = fd.read().split("\n")
        if (len(lines) > (linesback+1)) or atstart:
            break

        avgcharsperline=avgcharsperline * 1.3

    if len(lines) > linesback:
        start = len(lines) - linesback - 1
    else:
        start = 0

    return lines[start:len(lines)-1]

def do_tail(filename, lines, follow, func=handle_line):
    fd = open(filename, 'r')

    for line in tail_lines(fd, lines):
        func(line + "\n")

    if not follow:
        return

    while 1:
        where = fd.tell()
        line = fd.readline()
        if not line:
            fd_results = os.fstat(fd.fileno())
            try:
                st_results = os.stat(filename)
            except OSError:
                st_results = fd_results

            if st_results[1] == fd_results[1]:
                time.sleep(1)
                fd.seek(where)
            else:
                print "%s changed inode numbers from %d to %d" % (filename, fd_results[1], st_results[1])
                fd = open(filename, 'r')
        else:
            func(line)

def main(argv = sys.argv):
    parser = OptionParser()
    parser.add_option("-n", "--number", action="store", type="int", dest = "number", default=10)
    parser.add_option("-f", "--follow", action="store_true", dest = "follow", default=0)
    (options, args) = parser.parse_args()
    do_tail(args[0], options.number, options.follow, handle_line)

if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        pass
