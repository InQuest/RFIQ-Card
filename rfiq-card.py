#!/usr/bin/env python

import os
import re
import sys
import json
import time
import datetime
import inquestlabs
import threading

"""
Notes:
    - metadata must be superset of all JSON.
    - multiprocessing has to be swapped with threading (jython behind the scenes).
    - requests package may need to be converted to wheel.
    - update timeout to be .9 * RF_TIMEOUT
    - MAX_LIST controls max number of returned items.
"""

DEBUG     = True
TIMEOUT   = 90
DATASTORE = {}
MAX_LIST  = 5
OVERVIEW  = "InQuest Labs Intelligence is sourced from numerous locations in parallel and comprises of file data (DFI),"
OVERVIEW += " aggregate reputation information (Rep-DB/OSINT), and crawled/relevant conversations (IOC-DB/SOCMINT)."
OVERVIEW += " Follow the permalinks for further details, a max of %d entries are displayed here." % MAX_LIST

# hard-coded API key.
APIKEY = None

########################################################################################################################
def commify (number):
    """
    If given a number, format it into a human readable string with commas, otherwise return the supplied value back.
    """

    # if we're not dealing with a number, return the original value.
    try:
        int(number)
    except:
        return number

    # convert from integer to one with strings.
    number     = str(number)
    processing = 1
    regex      = re.compile(r"^(-?\d+)(\d{3})")

    while processing:
        (number, processing) = regex.subn(r"\1,\2", number)

    return number


########################################################################################################################
def groom_dfidb (data):
    """
    data is a list.
    """

    malicious = 0
    groomed   = []
    ok_keys   = \
    [
        "classification", "file_type", "first_seen", "last_modified", "num_iocs", "tags",
        "len_code", "len_context", "len_metadata", "len_ocr", "mime_type", "sha256", "size",
    ]

    for d in data[:MAX_LIST]:
        gd = {}

        # add all approved keys that contain a value.
        for k, v in d.items():
            if k in ok_keys:
                if v not in ["", None]:
                    gd[k] = commify(v)

        # if any file is malicious, raise the malicious flag.
        if d['classification'] == "MALICIOUS":
            malicious += 1

        # splice in a direct link.
        gd['permalink'] = "https://labs.inquest.net/rf/dfi/sha256/%s" % d['sha256']

        # splice in MAV detection ratio (when available).
        vt_positives = d.get("vt_positives")

        if vt_positives is not None:
            gd['mav_ratio'] = "%d%%" % int(float(vt_positives) / 60 * 100)

        # splice in InQuest ML classificaiton (when available).
        ml_score = d.get("inquest_ml_score")

        if ml_score is None:
            pass

        elif ml_score == -1:
            gd['ml_label'] = "BENIGN"

        elif ml_score == 0:
            gd['ml_label'] = "UNKNOWN"

        else:
            gd['ml_label'] = "MALICIOUS with %d%% confidence" % int(ml_score * 100)

        # add to groomed list.
        groomed.append(gd)

    # return data and overview.
    overview = "Found %d file hits under DFI, %d of which look malicious" % (len(data), malicious)
    return groomed, overview


########################################################################################################################
def groom_iocdb (data):
    """
    data is a list.
    """

    groomed = []
    ok_keys = \
    [
        "artifact", "artifact_type", "created_date", "reference_link", "reference_text",
    ]

    for d in data[:MAX_LIST]:
        gd = {}

        # add all approved keys that contain a value.
        for k, v in d.items():
            if k in ok_keys:
                if v not in ["", None]:
                    gd[k] = commify(v)

        # splice in a direct link.
        gd['permalink'] = "https://labs.inquest.net/rf/iocdb/search/%s" % d['artifact']

        # add to groomed list.
        groomed.append(gd)

    # high level overview.
    overview = "Found %d references under IOC-DB, InQuest Labs curation of SOCMINT data." % len(data)

    # return data and overview.
    return groomed, overview


########################################################################################################################
def groom_repdb (data):
    """
    data is a list.
    """

    groomed = []
    ok_keys = \
    [
        "created_date", "data", "data_type", "derived_data", "derived_type", "source", "source_url",
    ]

    for d in data[:MAX_LIST]:
        gd = {}

        # add all approved keys that contain a value.
        for k, v in d.items():
            if k in ok_keys:
                if v not in ["", None]:
                    gd[k] = commify(v)

        # splice in a direct link.
        gd['permalink'] = "https://labs.inquest.net/rf/repdb/search/%s" % d['data']

        # add to groomed list.
        groomed.append(gd)

    # return data and overview.
    overview = "Found %d references under Rep-DB, InQuest Labs aggregation of OSINT data." % len(data)
    return groomed, overview


########################################################################################################################
def groom_lookup (data):
    """
    data is a dictionary.
    """

    groomed = {}
    ok_keys = \
    [
        # shared keys.
        "indicator",

        # IP keys
        "asn", "asn_cidr", "asn_country_code", "asn_date", "asn_description", "asn_registry",

        # domain keys.
        "created_on", "dynamic_dns", "expires_on", "global_rank", "has_dnssec", "ip_address", "name_servers",
        "registrant", "registrant_country", "registrar", "updated_on",
    ]

    for k, v in data.items():
        if k in ok_keys and v:
            groomed[k] = v

    # splice in a direct link.
    groomed['permalink'] = "https://labs.inquest.net/rf/search/%s" % data['indicator']

    return groomed, None


########################################################################################################################
def log (msg, minor=False):
    """
    If minor is raised, then only print when DEBUG=True
    """

    if minor and not DEBUG:
        return

    sys.stderr.write("[%s] %s\n" % (datetime.datetime.now().isoformat(), msg))


########################################################################################################################
def request (request_dict, auth_info):
    """
    entry port for RecordedFuture Intel Card.
    """

    # apikey priority order: hard coded, function supplied, configuration file.
    apikey = APIKEY

    if not apikey:
        apikey = auth_info.get("apikey")

    if not apikey and os.path.exists("api.key"):
        apikey = open("api.key").read().strip()

    if not apikey:
        raise Exception("no apikey found")

    # instantiate labs, pull indicator from request dictionary, setup shared variable response dictionary.
    labs = inquestlabs.inquestlabs_api(apikey, verify_ssl=False)
    ioc  = request_dict["entity"]["name"]
    kind = request_dict["entity"]["type"]
    jobs = []

    log("received kind=%s ioc=%s" % (kind, ioc))

    # spin out jobs for handling domain name lookups.
    if kind == "InternetDomainName":

        # Lookup API.
        job = threading.Thread(target=worker, args=(labs, groom_lookup, "lookup", ["domain", ioc]))
        job.setName("lookup-domain")
        jobs.append(job)
        job.start()

        # DFIdb.
        job = threading.Thread(target=worker, args=(labs, groom_dfidb, "dfi_search", ["ioc", "domain", ioc]))
        job.setName("dfi-domain")
        jobs.append(job)
        job.start()

        # REPdb.
        job = threading.Thread(target=worker, args=(labs, groom_repdb, "repdb_search", [ioc]))
        job.setName("rep-domain")
        jobs.append(job)
        job.start()

        # IOCdb.
        job = threading.Thread(target=worker, args=(labs, groom_iocdb, "iocdb_search", [ioc]))
        job.setName("ioc-domain")
        jobs.append(job)
        job.start()

    # spin out jobs for handling IP address lookups.
    elif kind == "IpAddress":

        # Lookup API.
        job = threading.Thread(target=worker, args=(labs, groom_lookup, "lookup", ["ip", ioc]))
        job.setName("lookup-ip")
        jobs.append(job)
        job.start()

        # DFIdb.
        job = threading.Thread(target=worker, args=(labs, groom_dfidb, "dfi_search", ["ioc", "ip", ioc]))
        job.setName("dfi-ip")
        jobs.append(job)
        job.start()

        # REPdb.
        job = threading.Thread(target=worker, args=(labs, groom_repdb, "repdb_search", [ioc]))
        job.setName("rep-ip")
        jobs.append(job)
        job.start()

        # IOCdb.
        job = threading.Thread(target=worker, args=(labs, groom_iocdb, "iocdb_search", [ioc]))
        job.setName("ioc-ip")
        jobs.append(job)
        job.start()

    # spin out jobs for handling URL lookups.
    elif kind == "URL":

        # DFIdb.
        job = threading.Thread(target=worker, args=(labs, groom_dfidb, "dfi_search", ["ioc", "url", ioc]))
        job.setName("dfi-url")
        jobs.append(job)
        job.start()

        # REPdb.
        job = threading.Thread(target=worker, args=(labs, groom_repdb, "repdb_search", [ioc]))
        job.setName("rep-url")
        jobs.append(job)
        job.start()

        # IOCdb.
        job = threading.Thread(target=worker, args=(labs, groom_iocdb, "iocdb_search", [ioc]))
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
        job = threading.Thread(target=worker, args=(labs, groom_dfidb, "dfi_search", ["hash", hash_kind, ioc]))
        job.setName("dfi-hash")
        jobs.append(job)
        job.start()

        # IOCdb.
        job = threading.Thread(target=worker, args=(labs, groom_iocdb, "iocdb_search", [ioc]))
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
def worker (labs, groomer, endpoint, arguments):
    """
    Wrapper function for threaded spin-outs.
    """

    global DATASTORE
    DATASTORE['permalink'] = "https://labs.inquest.net"
    DATASTORE['overview']  = [OVERVIEW]

    # call worker and fill relevant endpoint dictionary.
    log("worker-started:%s(%s)" % (endpoint, arguments), minor=True)
    data, overview = groomer(getattr(labs, endpoint)(*arguments))
    log("worker-completed:%s(%s)" % (endpoint, arguments), minor=True)

    # when available, save the data under the relevant endpoint.
    if data:
        DATASTORE[endpoint] = data

    # when available, expand the overview description.
    if overview:
        DATASTORE['overview'].append(overview)


########################################################################################################################
if __name__ == "__main__":

    # real-deal.
    if not "unit-test" in map(str.lower, sys.argv):
        from recordedfuture_extension_util.extension_util import make_request
        print("response:", make_request(request))
        sys.exit(0)

    # dry run / testing.
    auth_info = \
    {
        "apikey": open("api.key").read().strip()
    }

        # dry-run.
    print("unit testing mode with key: %s" % auth_info['apikey'])

    # Domain.
    request_dict = \
    {
        "entity":
        {
            "name": "cpcwiki.de",
            "type": "InternetDomainName"
        }
    }

    print("testing domain...")
    print(request(request_dict, auth_info))

    # IP.
    request_dict = \
    {
        "entity":
        {
            "name": "178.62.194.122",
            "type": "IpAddress"
        }
    }

    print("testing IP...")
    print(request(request_dict, auth_info))

    # Hash.
    request_dict = \
    {
        "entity":
        {
            "name": "38f04e48c23dba3596d1773c81cca0abd21a4caeb635d079ed3efcdae193c1bd",
            "type": "Hash"
        }
    }

    print("testing hash...")
    print(request(request_dict, auth_info))

    # URL.
    request_dict = \
    {
        "entity":
        {
            "name": "http://denytransactioni.site/xleet.zip",
            "type": "URL"
        }
    }

    print("testing url...")
    print(request(request_dict, auth_info))

    print("QED")
