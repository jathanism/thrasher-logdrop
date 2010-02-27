#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" 
Parses thrasher log to watch for activity.  
Interact with iptables or route upon detected actions.
"""

__author__ = 'Jathan McCollum <jathan+github@gmail.com>'
__version__ = '0.2'


import commands
import os
import re
import sys
import time
from optparse import OptionParser
import warnings


###############################
##   USER-SERVICABLE PARTS   ##
###############################

# Default method set here. Change this if you dare! Make sure it's a
# method listed in VALID_METHODS & ACTIONS.
DEFAULT_METHOD = 'iptables'

###############################
## END USER-SERVICABLE PARTS ##
###############################

# Interaction method can only be one of the following:
VALID_METHODS = ('iptables', 'route',)

# Mappings of actions and commands for use in interact()
# (If you add a new method, you must also and an action)
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
    """If interaction with filter method fails."""
    pass

class InteractionError(Exception): 
    """If interaction with filter method causes the program to exit."""
    pass


def interact(parts, method):
    """
    Intended to be a generic interface to future additions of route injection
    methods. Executes and returns status & output of the route injection command.

    Expects:
    * parts: Should be dictionary of line_parts broken up by handle_line
    * method: The method designated by opts.method

    Returns:
    * command = The command string executed (used for debug)
    * status = The return code of the command execution
    * output = You have one guess what this is
    """
    details = ACTIONS[method]
    command = details['command'] % (details[parts['action']], parts['attacker'])
    status, output = commands.getstatusoutput(command)
    activity[parts['attacker']] = (parts['action'], status,)
    
    return command, status, output

def handle_line(line):
    """
    Splits up a log entry & kicks off the route injection with the parts
    Tries to be informative. This output could probably use work.
    """
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
    Makes the program actlike TAIL(1). Borrowed from Python Cookbook.
    """
    avgcharsperline = 75

    while True:
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
    """Tail the file just like the standard 'tail' command.  Works as a pipe.

    You may execute it as if it were tail such as:

        % logdrop -n50 -f /var/log/thrashd.log

    Or as a pipe:

        % grep 1.2.3 /var/log/thrashd.log | logdrop
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
    """Another surprise function!"""
    if activity:
        print '\n%d lines filtered.\n' % len(activity)

    for ip in activity:
        print ip, activity[ip]

def parse_args():
    """What do you think this does?"""
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

    ## A little logic to automatically set opts.method to the chosen method 
    [setattr(opts, 'method', M) for M in VALID_METHODS 
            if M in opts.__dict__ and opts.__dict__[M]]
    print 'Route injection mode set to: %s' % opts.method.upper()

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
