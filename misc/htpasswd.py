#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2008-2013 Edgewall Software
# Copyright (C) 2008 Eli Carter
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#  3. The name of the author may not be used to endorse or promote
#     products derived from this software without specific prior
#     written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://trac.edgewall.org/.

import getpass
import optparse
import sys
import string
import random
import crypt


def salt():
    chars = string.ascii_letters + string.digits + '/.'
    return ''.join(random.choice(chars) for _ in range(2))


class HtpasswdFile:
    """A class for manipulating htpasswd files."""

    def __init__(self, filename, create=False):
        self.entries = []
        self.filename = filename
        if not create:
            self.load()

    def load(self):
        """Read the htpasswd file into memory."""
        self.entries = []
        with open(self.filename, 'r') as f:
            for line in f:
                username, pwhash = line.split(':')
                entry = [username, pwhash.rstrip()]
                self.entries.append(entry)

    def save(self):
        """Write the htpasswd file to disk"""
        with open(self.filename, 'w') as f:
            f.writelines("%s:%s\n" % (entry[0], entry[1])
                         for entry in self.entries)

    def update(self, username, password):
        """Replace the entry for the given user, or add it if new."""
        pwhash = crypt.crypt(password, salt())
        matching_entries = [entry for entry in self.entries
                            if entry[0] == username]
        if matching_entries:
            matching_entries[0][1] = pwhash
        else:
            self.entries.append([username, pwhash])

    def delete(self, username):
        """Remove the entry for the given user."""
        self.entries = [entry for entry in self.entries
                        if entry[0] != username]


def main():
    """
        %prog [-c] filename username
        %prog -b[c] filename username password
        %prog -D filename username
    """
    # For now, we only care about the use cases that affect tests/functional.py
    parser = optparse.OptionParser(usage=main.__doc__)
    parser.add_option('-b', action='store_true', dest='batch', default=False,
        help='Batch mode; password is passed on the command line IN THE CLEAR.'
        )
    parser.add_option('-c', action='store_true', dest='create', default=False,
        help='Create a new htpasswd file, overwriting any existing file.')
    parser.add_option('-D', action='store_true', dest='delete_user',
        default=False, help='Remove the given user from the password file.')

    options, args = parser.parse_args()

    def syntax_error(msg):
        """Utility function for displaying fatal error messages with usage
        help.
        """
        sys.stderr.write("Syntax error: " + msg)
        sys.stderr.write(parser.get_usage())
        sys.exit(1)

    # Non-option arguments
    if len(args) < 2:
        syntax_error("Insufficient number of arguments.\n")
    filename, username = args[:2]
    password = None
    if options.delete_user:
        if len(args) != 2:
            syntax_error("Incorrect number of arguments.\n")
    else:
        if len(args) == 3 and options.batch:
            password = args[2]
        elif len(args) == 2 and not options.batch:
            first = getpass.getpass("New password:")
            second = getpass.getpass("Re-type new password:")
            if first == second:
                password = first
            else:
                syntax_error("htpasswd: password verification error")
                return
        else:
            syntax_error("Incorrect number of arguments.\n")

    try:
        passwdfile = HtpasswdFile(filename, create=options.create)
    except IOError:
        syntax_error("File not found.\n")
    else:
        if options.delete_user:
            passwdfile.delete(username)
        else:
            passwdfile.update(username, password)
        passwdfile.save()


if __name__ == '__main__':
    main()
