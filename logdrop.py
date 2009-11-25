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
import platform
import warnings
import syslog

__version__ = 0.1

log_re  = re.compile(r'^(?P<timestamp>\w{3} \d\d \d\d:\d\d:\d\d) (?P<loghost>\d+\.\d+\.\d+\.\d+) (?P<instance>\S+): (?P<action>holding down|expired) address (?P<attacker>\d+\.\d+\.\d+\.\d+)\s?(?:triggered by (?P<trigger>\d+\.\d+\.\d+\.\d+))?') 

ACTIONS = {
    'holding down': 'I', # I = insert
    'expired': 'D',      # D = delete
}

activity = {}

## warnings
class IPTablesWarning(Warning): 
    """
    If interaction with iptables fails.
    """
    pass

## exceptions
class IPTablesError(Exception): 
    """
    If interaction with iptables causes the program to exit.
    """
    pass

## functions
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
    status, output = commands.getstatusoutput(cmd)

    activity[p['attacker']] = (p['action'], status,)
    
    return cmd, status, output

def handle_line(line):
    print line,

    line_parts  = log_re.match(line).groupdict()
    action      = line_parts['action']
    attacker    = line_parts['attacker']

    cmd, status, output = iptables_interact(line_parts)

    if status > 0:
        #warnings.warn('Problem interacting with iptables for %s' % p['attacker'], IPTablesWarning)
        warnings.warn('IP %s (%s)' % (attacker, output), IPTablesWarning)
        print '\t%s FAILURE' % attacker
    else:
        print '\t%s SUCCESS' % attacker
        
    print

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
    """
    Tail the file just like the standard 'tail' command.  Works as a pipe.
    """
    fd = open(filename, 'r')

    for line in tail_lines(fd, lines):
        func(line + "\n")

    if not follow:
        return

    while True:
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

def report_activity():
    if activity:
        print '\n%d lines filtered.\n' % len(activity)

    for ip in activity:
        print ip, activity[ip]

def main(argv=None):
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
    finally:
        report_activity()
