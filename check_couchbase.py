#!/usr/bin/env python
# -*- coding: utf-8; -*-
"""

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

check_couchbase.py is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>

Required libs:
- json
- sys
- optparse
- requests
- urllib
- subprocess


This plugin implements two checks:
1. Node status: node is active and healthy
2. Cluster overall status: memory, disk usage and
   make sure each node is active and healthy
3. XDCR health: this check looks at replication checkpoints
   and checkpoint failures. The pools/default/tasks endpoint
   is also checked for xdcr errors.

See ./check_couchbase.py -h for detailed options list

Author: Grzegorz "You can call me Greg" Adamowicz (gadamowicz@gstlt.info)
URL: http://gstlt.info

Version: 1.0

"""

from optparse import OptionParser
from optparse import OptionGroup
import requests
import sys
import urllib
from subprocess import check_output

nagios_codes = {
    'OK': {
        'exit_code': 0,
        'desc': 'OK'
    },
    'WARNING': {
        'exit_code': 1,
        'desc': 'WARNING'
    },
    'CRITICAL': {
        'exit_code': 2,
        'desc': 'CRITICAL'
    },
    'UNKNOWN': {
        'exit_code': 3,
        'desc': 'UNKNOWN'
    },
    'DEPENDENT': {
        'exit_code': 4,
        'desc': 'DEPENDENT'
    },
}

consul_locations = ['atl', 'hsv', 'phx']
valid_checks     = ['status', 'health', 'xdcr']

"""
   Print status message
"""
def print_output(msg):
    print msg

"""
    Do GET request
"""
def do_get(opts, url_pieces):
    url  = "http://%s:%s/%s" % (opts.hostname, opts.port, '/'.join(url_pieces))
    status = nagios_codes['UNKNOWN']
    json = None
    req  = None

    try:
        req = requests.get(url, auth=(opts.username, opts.password))
    except Exception:
        print("%s - error retrieving %s" % (status['desc'], url))
        sys.exit(status['exit_code'])

    try:
        json = req.json()
    except Exception:
        print("%s - exception parsing JSON response" % status['desc'])
        sys.exit(status['exit_code'])

    return json

"""
    Check to make sure (each) node is active and healthy
"""
def check_nodes(opts, nodes, search_node = None):
    status = None
    msg    = None

    # check status and clusterMembership
    for couch_node in nodes:
        if not search_node is None or couch_node["hostname"] == "%s:%s" % (opts.hostname, opts.port):
            msg = "%s: couchbase_status=%s clusterMembership=%s" % (opts.hostname, couch_node["status"],couch_node["clusterMembership"])
            if couch_node["status"] == "healthy" and couch_node["clusterMembership"] == "active":
                status = nagios_codes['OK']
            elif couch_node["status"] not in ("healthy", "warmup"):
                status = nagios_codes['CRITICAL']
            elif couch_node["status"] == "healthy" and couch_node["clusterMembership"] == "inactiveFailed":
                status = nagios_codes['WARNING']
            else:
                status = nagios_codes['WARNING']

            if not search_node is None or status['exit_code'] > 0:
                break

    return {'status': status, 'msg': "%s - %s" % (status['desc'], msg)}


"""
    Check if node is active and healthy
"""
def check_status(opts):
    json = do_get(opts, ['pools', 'nodes'])

    # check status and clusterMembership
    return check_nodes(opts, json['nodes'], "%s:%s" % (opts.hostname, opts.port))


"""
    Check overall cluster health
    1. If all nodes are active and healthy
    2. If memory usage is below warning/critical values
    3. If hdd usage is below warning/critical values
"""
def check_health(opts):
    json   = do_get(opts, ['pools', 'nodes'])
    status = nagios_codes['OK']
    msg    = "%s - %0.2f%% mem free, %0.2f%% disk free"

    # check make sure each node is active AND healthy
    nodes_status = check_nodes(opts, json['nodes'])
    if nodes_status['status']['exit_code'] > 0: return nodes_status

    # get mem usage
    mem_used = float(json['storageTotals']['ram']['used'])
    mem_total = float(json['storageTotals']['ram']['total'])
    mem_percentage = round((mem_used / mem_total) * 100, 2)

    # get hdd usage
    hdd_used = float(json['storageTotals']['hdd']['used'])
    hdd_total = float(json['storageTotals']['hdd']['total'])
    hdd_percentage = round((hdd_used / hdd_total) * 100, 2)

    # We now have all needed data. Do the checking.
    if mem_percentage >= opts.critical or hdd_percentage >= opts.critical:
        status = nagios_codes['CRITICAL']
    elif mem_percentage >= opts.warning or hdd_percentage >= opts.warning:
        status = nagios_codes['WARNING']

    return {'status': status, 'msg': msg % (status['desc'], 100.00 - mem_percentage, 100.00 - hdd_percentage)}


"""
    Check health of XDCR
    1. Check for errors: /pools/default/tasks
    2. Check some XDCR stats: num_checkpoints vs. num_failedckpts
"""
def check_xdcr(opts):
    # Checkpoints vs failed checkpoints
    json   = do_get(opts, ['pools', 'default', 'remoteClusters'])
    status = nagios_codes['OK']
    msg    = "OK - no replications to check on %s:%s" % (opts.hostname, opts.port)

    if len(json) == 0 or not json[0]['uuid']: return {'status': status, 'msg': msg}
    uuid = json[0]['uuid']

    endpoint = urllib.quote("replications/%s/%s/%s/" % (uuid, opts.source_bucket, opts.dest_bucket), safe='')
    url_pieces = ['pools', 'default', 'buckets', 'sessions', 'stats']

    chkpts_endpoint = endpoint + "num_checkpoints"
    chkpts = do_get(opts, url_pieces + [chkpts_endpoint])

    failed_chkpts_endpoint = endpoint + "num_failedckpts"
    failed_chkpts = do_get(opts, url_pieces + [failed_chkpts_endpoint])

    for node in chkpts['nodeStats']:
        # Return UNKNOWN if either node has 'undefined' stats
        if failed_chkpts['nodeStats'][node][-1] or chkpts['nodeStats'][node][-1] == 'undefined':
            return {
                'status': nagios_codes['UNKNOWN'],
                'msg': "UNKNOWN - something went wrong, do the source and destination buckets (%s, %s) exist?" % (opts.source_bucket, opts.dest_bucket)
            }

        error_percentage = round((float(failed_chkpts['nodeStats'][node][-1]) / float(chkpts['nodeStats'][node][-1])) * 100, 2)
        if error_percentage >= opts.critical:
            status = nagios_codes['CRITICAL']
            print chkpts['nodeStats'][node][-1]
        elif error_percentage >= opts.warning:
            status = nagios_codes['WARNING']

        if status['exit_code'] > 0:
            return {'status': status, 'msg': "%s - %0.2f%% of checkpoints failed during replication." % (status['desc'], error_percentage)}

    # Check to see if there are any XDCR errors
    json = do_get(opts, ['pools', 'default', 'tasks'])
    for task in json:
        if task['type'] == 'xdcr' and len(task['errors']) > 0:
            status = nagios_codes['CRITICAL']

        if status['exit_code'] > 0:
            return {'status': status, 'msg': "CRITICAL - XDCR error(s) found: %s" % task['errors'][-1]}

    return {'status': status, 'msg': "OK - no issues found"}


"""
    Get service IP from Consul
    1. Loop over Consul hosts
    2. Break when we get an answer
    3. Return first IP
"""
def ask_consul(opts):
    consul_hostname = "consul.%s.dealnews.net" % opts.consul_loc
    opts.consul_svc = "%s.service.%s.consul" % (opts.consul_svc, opts.consul_loc)
    svc_hosts = []

    consul_hosts = check_output(["dig", "+short", "+retry=3", consul_hostname]).rstrip().split("\n")

    for consul_host in consul_hosts:
        svc_hosts = check_output(["dig", "-p8600", "+short", "+retry=3", "@%s" % consul_host, opts.consul_svc]).rstrip().split("\n")
        opts.consul_host = consul_host

        if svc_hosts:
            break

    return svc_hosts.pop(0)


""" Check Options """
def check_options(opts):
    status = nagios_codes['UNKNOWN']
    msg    = None

    if opts.hostname == None and (not opts.consul_loc or not opts.consul_svc):
        msg = "A host (-H, --host) OR consul service name (-s, --consul-svc) AND consul location (-l, --consul-loc) must be specified.'"

    if opts.consul_loc not in consul_locations:
        msg = "Consul location must be one of %s" % ', '.join(consul_locations)

    if opts.username == None or opts.password == None:
        msg = "must pass username AND password"

    if opts.check_type == 'health' or opts.check_type == 'xdcr':
        if opts.critical == None or opts.warning == None:
            msg = "please provide critical and warning values (percentage used mem or hdd)"

        if opts.critical < opts.warning:
            msg = "critical value must be larger than warning"

    if opts.check_type == None:
        msg = "check status or check health options must be provided"

    if not msg is None:
        print "%s - %s" % (status['desc'], msg)
        return 1

    return 0

""" Lowercase """
def lower_option(option, opt_str, value, parser):
    setattr(parser.values, option.dest, value.lower())


""" Main program """
def main():
    """
    Options definition
    See: http://docs.python.org/2/library/optparse.html
    """
    usage = """%prog -H hostname [-P port] -u username -p password -w XX -c XX [-s|-b]

Check health/status of Couchbase cluster/node

* Note: Either a host argument OR Consul service name AND location arguments must be passed.
        If a Consul service name and location are passed this script will use the dig command
        line tool to attempt to get an IP address from Consul.
    """

    parser = OptionParser(usage=usage)

    host_api = OptionGroup(parser, 'Host/API Options')
    host_api.add_option("-H", "--hostname", dest="hostname", help="Cluster host name or IP address")
    host_api.add_option("-l", "--consul-loc", dest="consul_loc", help="Consul location, must be one of: %s" % ', '.join(consul_locations), type="string", action="callback", callback=lower_option)
    host_api.add_option("-s", "--consul-svc", dest="consul_svc", help="Consul service (default: couchbase)", default="couchbase", type="string", action="callback", callback=lower_option)
    host_api.add_option("-P", "--port", dest="port", default="8091", help="API port (default: 8091)")
    host_api.add_option("-u", "--username", dest="username", default="couchbase", help="User name used to connect to Couchbase server (default: couchbase)")
    host_api.add_option("-p", "--password", dest="password", help="Password")
    parser.add_option_group(host_api)

    check = OptionGroup(parser, 'Check Options')
    check.add_option("-k", "--check-type", type="string", action="callback", dest="check_type", default="status", callback=lower_option, help=("Check type, must be one"
    " of: %s (default: status)" % ', '.join(valid_checks)))
    check.add_option("-w", "--warning", type="float", dest="warning", help="Warning value % (percent), eg. -w 95")
    check.add_option("-c", "--critical", type="float", dest="critical", help="Critical value % (percent), eg. -c 98")
    check.add_option("--source-bucket", type="string", dest="source_bucket", default="sessions", action="store", help="Name of source bucket for XDCR checks (default: sessions)")
    check.add_option("--dest-bucket", type="string", dest="dest_bucket", default="sessions", action="store", help="Name of destination bucket for XDCR checks (default: sessions)")
    parser.add_option_group(check)

    (options, args) = parser.parse_args()

    if check_options(options) > 0:
        sys.exit(nagios_codes['UNKNOWN']['exit_code'])

    if not options.hostname:
        options.hostname = ask_consul(options)

    if not options.hostname:
        print("CRITICAL - No answer from %s for %s, cluster may be down." % (options.consul_host, options.consul_svc))
        sys.exit(nagios_codes['CRITICAL']['exit_code'])

    check_return = None

    if options.check_type == 'status':
        check_return = check_status(options)

    if options.check_type == 'health':
        check_return = check_health(options)

    if options.check_type == 'xdcr':
        check_return = check_xdcr(options)

    if check_return is None:
        status = nagios_codes['UNKNOWN']
        check_return = {'status': status, 'msg': "UNKNOWN - not enough options given, see %prog -h for help"}

    print_output(check_return['msg'])
    sys.exit(check_return['status']['exit_code'])

if __name__ == "__main__":
    main()
