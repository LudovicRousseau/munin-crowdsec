#!/usr/bin/env python3
# -*- python -*-

"""
=head1 NAME

crowdsec - return crowdsec alerts results

=head1 AUTHOR

Copyright (c) 2023 Ludovic Rousseau

=head1 LICENSE

GNU GPLv3 or any later version

=begin comment

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

=end comment

=cut
"""

import csv
import sys
import os
import time
import json

try:
    FILENAME = os.environ["FILENAME"]
except KeyError:
    FILENAME = "/var/run/munin/crowdsec.raw"


def get_data():
    # the filename is something like
    # /var/lib/munin-node/plugin-state/nobody/crowdsec-
    previous_data_filename = os.environ.get('MUNIN_STATEFILE', 'crowdsec-STATEFILE')
    try:
        with open(previous_data_filename) as f:
            data = json.load(f)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        # starts with empty dictionnaries
        data = {'countries': {}, 'reasons': {}}

    # reuse previous data
    countries = dict()
    for country in data["countries"]:
        countries[country] = 0
    reasons = dict()
    for reason in data["reasons"]:
        reasons[reason] = 0

    current_time = int(time.time())

    with open(FILENAME) as csvfile:
        reader = csv.reader(csvfile)

        # skip the header
        next(reader)

        for row in reader:
            reason = row[3]
            country = row[5]
            # print(reason, country)

            if reason in reasons:
                reasons[reason] += 1
            else:
                reasons[reason] = 1

            if country in countries:
                countries[country] += 1
            else:
                countries[country] = 1

            data["reasons"][reason] = current_time
            data["countries"][country] = current_time

    # remove old data
    to_remove = list()
    for country in data["countries"]:
        if current_time - data["countries"][country] > 365 * 24 * 60 * 60:
            to_remove.append(country)
    for country in to_remove:
        del data["countries"][country]

    to_remove = list()
    for reason in data["reasons"]:
        if current_time - data["reasons"][reason] > 365 * 24 * 60 * 60:
            to_remove.append(reason)
    for reason in to_remove:
        del data["reasons"][reason]

    # update JSON file
    with open(previous_data_filename, "w") as f:
        json.dump(data, f)

    if output_type == "countries":
        data = countries
    else:
        data = reasons

    return data


def report():
    data = get_data()
    for d in sorted(data):
        print("{}.value {}".format(d, data[d]))


def config():
    print("graph_args")
    print("graph_vlabel")
    print("graph_category network")
    if output_type == "countries":
        print("graph_title CrowdSec Alerts Countries")
        print("graph_info countries origin of attacks")
    else:
        print("graph_title CrowdSec Alerts Reasons")
        print("graph_info type of attacks")
    print("graph_total Total")
    data = get_data()
    s = "AREA"
    for d in sorted(data):
        print("{}.label {}".format(d, d))
        print("{}.draw {}".format(d, s))
        s = "STACK"


def main():
    global output_type

    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        command = ""

    if "countries" in sys.argv[0]:
        output_type = "countries"
    else:
        output_type = "reasons"

    if command == "config":
        config()
    elif command == "debug":
        debug()
    else:
        report()


if __name__ == "__main__":
    main()
