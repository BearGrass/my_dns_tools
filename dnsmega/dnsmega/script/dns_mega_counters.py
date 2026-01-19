#!/home/tops/bin/python

# -*- coding: utf-8 -*-

# filename   : dnsmega_counters
# created at : 2016.7.27 14:35:59
# author     : mo gu <mogu.lwp@alibaba-inc.com>

import os
import sys
import subprocess
try:
    import json
except ImportError:
    import simplejson as json

def runcmd(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    rcode = process.returncode
    return rcode, out, err

def locate_named_stats():
    if os.path.exists("/proc/dnsmega/counters"):
        return "/proc/dnsmega/counters"
    return None

def file_exist(fn):
    h = open(fn, 'r')
    h.close()

def read_stats():
    try:
        return json.loads(open("/tmp/.dnsmega_counters").read())
    except:
        return None

def write_stats(dataset):
    h = open("/tmp/.dnsmega_counters", "w")
    h.write(json.dumps(dataset))
    h.close()

def cal_stats(d1, d2, t1, t2):
    dataset = {}
    for k in d2:
        dataset[k] = int((d2[k] - d1[k]) / (t2 - t1))
        if dataset[k] < 0:
            dataset[k] = 0
    return dataset

def dump_mega_counters(named_stats):
    dataset = dict()
    dataset0 = dict(dataset)

    runcmd("cat %s" % named_stats)
    for line in open(named_stats).readlines():
        dataset[line.split()[0]] = int(line.split()[2])
    orgi = read_stats()
    try:
        t1 = os.stat('/tmp/.dnsmega_counters').st_mtime
        t2 = os.stat(named_stats).st_mtime
    except:
        pass
    write_stats(dataset)
    if orgi:
        return cal_stats(orgi, dataset, t1, t2)
    return dataset0

def main():
    named_stats = locate_named_stats()
    file_exist(named_stats)
    print(json.dumps(dict(collection_flag = 0,
                          error_info = '',
                          MSG = [dump_mega_counters(named_stats)]
                          )))


if __name__ == '__main__':
    main()
