#!/usr/bin/env python

""" 
Parses thrasher log to watch for activity.  
Interact with iptables or route upon detected actions.

"""

import commands
import os
import re
import sys
import time
from optparse import OptionParser
import warnings

__version__ = 0.2


###############################
##   USER-SERVICABLE PARTS   ##
###############################

# Default method set here. Change this if you dare!
DEFAULT_METHOD='iptables'

###############################
## END USER-SERVICABLE PARTS ##
###############################

# Interaction method can only be one of the following:
VALID_METHODS = ('iptables', 'route',)

# Mappings of actions and commands for use in interact()
ACTIONS = {
    'route': {
        'holding down': 'add',
        'expired': 'del',
        'command': "route %s -host %s reject",
    },
    'iptables': {
        'holding down': 'I', # I = insert
        'expired': 'D',      # D = delete
        'command': "iptables -%s INPUT -s %s -j DROP",
    },
}

# Will be filled up with the activity. Go figure!
activity = {}

# Let's hope this never changes.
log_re  = re.compile(r'^(?P<timestamp>\w{3} \d\d \d\d:\d\d:\d\d) (?P<loghost>\d+\.\d+\.\d+\.\d+) (?P<instance>\S+): (?P<action>holding down|expired) address (?P<attacker>\d+\.\d+\.\d+\.\d+)\s?(?:triggered by (?P<trigger>\d+\.\d+\.\d+\.\d+))?') 


class InteractionWarning(Warning): 
    """
    If interaction with filter method fails.
    """
    pass

class InteractionError(Exception): 
    """
    If interaction with filter method causes the program to exit.
    """
    pass


def interact(parts, method):
    details = ACTIONS[method]
    command = details['command'] % (details[parts['action']], parts['attacker'])
    status, output = commands.getstatusoutput(command)
    activity[parts['attacker']] = (parts['action'], status,)
    
    return command, status, output

def handle_line(line):
    print line,

    line_parts = log_re.match(line).groupdict()
    action = line_parts['action']
    attacker = line_parts['attacker']

    (cmd, status, output) = interact(line_parts, method=opts.method)

    if status > 0:
        warnings.warn('IP %s (%s)' % (attacker, output), InteractionWarning)
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

def parse_args():
    """
    What do you think this does?

    """
    USAGE = "usage: %prog [OPTION]... [FILE]..."

    parser = OptionParser(usage=USAGE)
    parser.add_option("-f", "--follow", action="store_true", dest="follow", default=0,
                     help="output appended data as the file grows; just like tail")
    parser.add_option("-n", "--number", action="store", type="int", dest="number", default=10,
                     help="output  the  last N lines, instead of the last 10; just like tail")
    parser.add_option("-i", "--iptables", action="store_true", dest="iptables", default=False, 
                     help="use iptables method [default]; equivalent to --method=iptables")
    parser.add_option("-r", "--route", action="store_true", dest="route", default=False,
                     help="use route method; equivalent to --method=route")
    parser.add_option("-m", "--method", action="store", type="string", dest="method", default=DEFAULT_METHOD,
                     metavar="METHOD", help="use specified method for interaction")

    (opts, args) = parser.parse_args()

    def _err(msg):
        parser.print_help()
        parser.error(msg)
        sys.exit(-1)

    if not opts or not args: 
        parser.print_help()
        sys.exit(0)

    if opts.route and opts.iptables:
        _err("Can't force -i and -r. Pick one.")

    if opts.method and opts.method not in VALID_METHODS:
        _err("Pick a valid method: %s" % str(VALID_METHODS))

    if opts.route:
        opts.method = 'route'

    if opts.iptables:
        opts.method = 'iptables'

    return opts, args

def main():
    do_tail(args[0], opts.number, opts.follow, handle_line)


if __name__ == "__main__":
    (opts, args) = parse_args()

    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        report_activity()
