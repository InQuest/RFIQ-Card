#!/usr/bin/env python

import sys
import json
import time
import datetime
import inquestlabs
import threading

"""
- metadata must be superset of all JSON.
- multiprocessing has to be swapped with threading (jython behind the scenes).
- requests package may need to be converted to wheel.
- update timeout to be .9 * RF_TIMEOUT
"""

DEBUG     = True
TIMEOUT   = 30
DATASTORE = {}

########################################################################################################################
def log (msg, minor=False):
    """
    If minor is raised, then only print when DEBUG=True
    """

    if minor and not DEBUG:
        return

    sys.stderr.write("[%s] %s\n" % (datetime.datetime.now().isoformat(), msg))


########################################################################################################################
def worker (labs, endpoint, arguments):
    """
    Wrapper function for threaded spin-outs.
    """

    global DATASTORE

    log("worker:%s(%s)" % (endpoint, arguments), minor=True)
    DATASTORE[endpoint] = getattr(labs, endpoint)(*arguments)


########################################################################################################################
def request (request_dict, auth_info):
    """
    entry port for RecordedFuture Intel Card.
    """

    # instantiate labs, pull indicator from request dictionary, setup shared variable response dictionary.
    labs = inquestlabs.inquestlabs_api(auth_info["password"])
    ioc  = request_dict["entity"]["name"]
    kind = request_dict["entity"]["type"]
    jobs = []

    log("received kind=%s ioc=%s" % (kind, ioc))

    # spin out jobs for handling domain name lookups.
    if kind == "InternetDomainName":

        # Lookup API.
        job = threading.Thread(target=worker, args=(labs, "lookup", ["domain", ioc]))
        job.setName("lookup-domain")
        jobs.append(job)
        job.start()

        # DFIdb.
        job = threading.Thread(target=worker, args=(labs, "dfi_search", ["ioc", "domain", ioc]))
        job.setName("dfi-domain")
        jobs.append(job)
        job.start()

        # REPdb.
        job = threading.Thread(target=worker, args=(labs, "repdb_search", [ioc]))
        job.setName("rep-domain")
        jobs.append(job)
        job.start()

        # IOCdb.
        job = threading.Thread(target=worker, args=(labs, "iocdb_search", [ioc]))
        job.setName("ioc-domain")
        jobs.append(job)
        job.start()

    # spin out jobs for handling IP address lookups.
    elif kind == "IpAddress":

        # Lookup API.
        job = threading.Thread(target=worker, args=(labs, "lookup", ["ip", ioc]))
        job.setName("lookup-ip")
        jobs.append(job)
        job.start()

        # DFIdb.
        job = threading.Thread(target=worker, args=(labs, "dfi_search", ["ioc", "ip", ioc]))
        job.setName("dfi-ip")
        jobs.append(job)
        job.start()

        # REPdb.
        job = threading.Thread(target=worker, args=(labs, "repdb_search", [ioc]))
        job.setName("rep-ip")
        jobs.append(job)
        job.start()

        # IOCdb.
        job = threading.Thread(target=worker, args=(labs, "iocdb_search", [ioc]))
        job.setName("ioc-ip")
        jobs.append(job)
        job.start()

    # spin out jobs for handling URL lookups.
    elif kind == "URL":

        # DFIdb.
        job = threading.Thread(target=worker, args=(labs, "dfi_search", ["ioc", "url", ioc]))
        job.setName("dfi-url")
        jobs.append(job)
        job.start()

        # REPdb.
        job = threading.Thread(target=worker, args=(labs, "repdb_search", [ioc]))
        job.setName("rep-url")
        jobs.append(job)
        job.start()

        # IOCdb.
        job = threading.Thread(target=worker, args=(labs, "iocdb_search", [ioc]))
        job.setName("ioc-url")
        jobs.append(job)
        job.start()

    # spin out jobs for handling hash lookups.
    elif kind == "Hash":

        # what kind of hash are we dealing with?
        if labs.is_md5(ioc):
            hash_kind = "md5"
        elif labs.is_sha1(ioc):
            hash_kind = "sha1"
        elif labs.is_sha256(ioc):
            hash_kind = "sha256"
        elif labs.is_sha512(ioc):
            hash_kind = "sha512"
        else:
            raise Exception("invalid hash kind")

        # DFIdb.
        job = threading.Thread(target=worker, args=(labs, "dfi_search", ["hash", hash_kind, ioc]))
        job.setName("dfi-hash")
        jobs.append(job)
        job.start()

        # IOCdb.
        job = threading.Thread(target=worker, args=(labs, "iocdb_search", [ioc]))
        job.setName("ioc-url")
        jobs.append(job)
        job.start()

    log("waiting up to %s seconds for %d jobs to complete...." % (TIMEOUT, len(jobs)), minor=True)

    # wait for jobs to complete, up to TIMEOUT.
    start = time.time()

    while time.time() - start <= TIMEOUT:
        if not any(job.is_alive() for job in jobs):
            # all the processes are done, break now.
            break

        # this prevents CPU hogging.
        time.sleep(.5)

    # we only enter this if we didn't 'break' above.
    else:
        log("timeout reached, the following jobs failed to complete...")
        for job in jobs:
            if job.is_alive():
                log("job never completed: %s" % job.getName())
            else:
                job.join()

    # record completion time.
    elapsed = time.time() - start
    log("completed query in %d seconds." % elapsed, minor=True)

    # return results.
    return json.dumps(DATASTORE)


########################################################################################################################
if __name__ == "__main__":
    auth_info = \
    {
        "username": "user",
        "password": "pass"
    }

    # Domain.
    request_dict = \
    {
        "entity":
        {
            "name": "recordedfuture.com",
            "type": "InternetDomainName"
        }
    }

    print(request(request_dict, auth_info))

    # IP.
    request_dict = \
    {
        "entity":
        {
            "name": "8.8.8.8",
            "type": "IpAddress"
        }
    }

    print(request(request_dict, auth_info))

    # Hash.
    request_dict = \
    {
        "entity":
        {
            "name": "bd5acbbfc5c2c8b284ec389207af5759",
            "type": "Hash"
        }
    }

    print(request(request_dict, auth_info))

    # URL.
    request_dict = \
    {
        "entity":
        {
            "name": "http://180.214.239.67/j/p7g/inc/",
            "type": "URL"
        }
    }

    print(request(request_dict, auth_info))
