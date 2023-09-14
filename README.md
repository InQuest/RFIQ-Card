# RFIQ-Card
Recorded Future InQuest Labs Integration

This repository houses a Recorded Future Intelligece Card Extension that leverages the data behind [InQuest Labs](https://labs.inquest.net) to enrich indicators including IPs, domains, URLs, and file hashes. Formally, the accepted IOC kinds include:

* URLs (`URL`)
* Domain Names (`InternetDomainName`)
* IPv4 Addresses (`IpAddress`)
* MD5, SHA1, SHA256, SHA512 (`Hash`)

## Building

Manually:

```bash
tar zcvf rfiq_extension.tgz docopt.py extension.json inquestlabs.py iq_full.png iq_thumbnail.png metadata.json requests/ rfiq-card.py
```

Automatically:

```bash
./build.sh
```

## Example Output

Run with argument `unit-test` to run an example indicator through each of the endpoints.

```
$ python rfiq-card.py unit-test
unit testing mode...
testing domain...
[2022-01-03T20:31:51.651998] received kind=InternetDomainName ioc=recordedfuture.com
[2022-01-03T20:31:51.652079] worker-started:lookup(['domain', 'recordedfuture.com'])
[2022-01-03T20:31:51.652546] worker-started:dfi_search(['ioc', 'domain', 'recordedfuture.com'])
[2022-01-03T20:31:51.652643] worker-started:repdb_search(['recordedfuture.com'])
[2022-01-03T20:31:51.652721] worker-started:iocdb_search(['recordedfuture.com'])
[2022-01-03T20:31:51.652747] waiting up to 30 seconds for 4 jobs to complete....
[2022-01-03T20:31:52.351134] worker-completed:lookup(['domain', 'recordedfuture.com'])
[2022-01-03T20:31:52.735748] worker-completed:iocdb_search(['recordedfuture.com'])
[2022-01-03T20:31:53.759610] worker-completed:dfi_search(['ioc', 'domain', 'recordedfuture.com'])
[2022-01-03T20:31:57.138739] worker-completed:repdb_search(['recordedfuture.com'])
[2022-01-03T20:31:57.188064] completed query in 5 seconds.
{"lookup": {"created_on": "2009-01-04T20:10:36", "dynamic_dns": null, "expires_on": "2022-10-02T03:59:59", "global_rank": 21255, "has_dnssec": true, "ip_address": "104.18.12.124", "name_servers": "[\"leah.ns.cloudflare.com\", \"hugh.ns.cloudflare.com\"]", "registrant": "", "registrant_country": "", "registrar": "Name.com, Inc.", "updated_on": "2021-09-09T16:41:54"}, "iocdb_search": [], "dfi_search": [{"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-12-22T08:27:21", "last_modified": "2021-12-22T08:33:16", "len_code": 0, "len_context": 1049058, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "34c927e9914d1c0b39c780ffb62e4fe2d66eb4d2790e56318a894b1796eb1ad4", "size": 967104}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-12-22T08:27:27", "last_modified": "2021-12-22T08:32:11", "len_code": 0, "len_context": 0, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "d08db6d5727687ac9090111b3e8e386da57a105dca0612419237ad48e50d5020", "size": 1608029}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-12-22T08:27:18", "last_modified": "2021-12-22T08:32:08", "len_code": 0, "len_context": 0, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "762efcaec9dabab9820e1f2b5b6b2cb7d2101347328319a884a96398904e564a", "size": 801984}, {"attribute": "domain", "classification": "UNKNOWN", "file_type": "PPT", "first_seen": "2021-12-15T01:28:30", "last_modified": "2021-12-15T01:40:30", "len_code": 0, "len_context": 600, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation", "sha256": "ef0fe7f327daa7e7160bc83ec583c70b852fe8d92404dbe832fd2563aff4e2e2", "size": 9412617}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-12-08T15:57:17", "last_modified": "2021-12-08T16:00:17", "len_code": 0, "len_context": 1049516, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "a4c1344872d7e838317a6704b6112bf0775279150dd625cd597473c94d74f39a", "size": 1585096}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-11-08T14:29:14", "last_modified": "2021-11-08T14:31:36", "len_code": 0, "len_context": 1049516, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "15a44677ab22f65cffcd3e9642d020846a922ea739eca7be0bf74876564105bb", "size": 1585904}, {"attribute": "domain", "classification": "UNKNOWN", "file_type": "XLS", "first_seen": "2021-10-15T17:04:21", "last_modified": "2021-10-15T17:14:23", "len_code": 0, "len_context": 0, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "b01e5db107ed26b0db635cf8ead970d7d4fdc267c6bd2047e6e502a773409844", "size": 6922066}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-10-07T17:19:21", "last_modified": "2021-10-07T17:21:25", "len_code": 7933, "len_context": 315935, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "7d2ae2b14c0249d3390fd35869691227f83ca1a2aea9c6cff7f45c27c0c27320", "size": 1709460}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-10-06T11:33:27", "last_modified": "2021-10-06T11:35:36", "len_code": 0, "len_context": 1049203, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "6ddae6a0520a9a40d5a5dd7f211f154c34365e4e79404eda78df1c85f1dfed7c", "size": 810230}], "repdb_search": []}
testing IP...
[2022-01-03T20:31:57.188687] received kind=IpAddress ioc=8.8.8.8
[2022-01-03T20:31:57.188866] worker-started:lookup(['ip', '8.8.8.8'])
[2022-01-03T20:31:57.189150] worker-started:dfi_search(['ioc', 'ip', '8.8.8.8'])
[2022-01-03T20:31:57.189602] worker-started:repdb_search(['8.8.8.8'])
[2022-01-03T20:31:57.190193] waiting up to 30 seconds for 4 jobs to complete....
[2022-01-03T20:31:57.189677] worker-started:iocdb_search(['8.8.8.8'])
[2022-01-03T20:31:57.659813] worker-completed:lookup(['ip', '8.8.8.8'])
[2022-01-03T20:31:58.282805] worker-completed:iocdb_search(['8.8.8.8'])
[2022-01-03T20:32:02.708260] worker-completed:repdb_search(['8.8.8.8'])
[2022-01-03T20:32:27.422201] timeout reached, the following jobs failed to complete...
[2022-01-03T20:32:27.422658] job never completed: dfi-ip
[2022-01-03T20:32:27.422736] completed query in 30 seconds.
{"lookup": {"asn": "15169", "asn_cidr": "8.8.8.0/24", "asn_country_code": "US", "asn_date": "1992-12-01", "asn_description": "GOOGLE, US", "asn_registry": "arin"}, "iocdb_search": [], "dfi_search": [{"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-12-22T08:27:21", "last_modified": "2021-12-22T08:33:16", "len_code": 0, "len_context": 1049058, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "34c927e9914d1c0b39c780ffb62e4fe2d66eb4d2790e56318a894b1796eb1ad4", "size": 967104}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-12-22T08:27:27", "last_modified": "2021-12-22T08:32:11", "len_code": 0, "len_context": 0, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "d08db6d5727687ac9090111b3e8e386da57a105dca0612419237ad48e50d5020", "size": 1608029}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-12-22T08:27:18", "last_modified": "2021-12-22T08:32:08", "len_code": 0, "len_context": 0, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "762efcaec9dabab9820e1f2b5b6b2cb7d2101347328319a884a96398904e564a", "size": 801984}, {"attribute": "domain", "classification": "UNKNOWN", "file_type": "PPT", "first_seen": "2021-12-15T01:28:30", "last_modified": "2021-12-15T01:40:30", "len_code": 0, "len_context": 600, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation", "sha256": "ef0fe7f327daa7e7160bc83ec583c70b852fe8d92404dbe832fd2563aff4e2e2", "size": 9412617}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-12-08T15:57:17", "last_modified": "2021-12-08T16:00:17", "len_code": 0, "len_context": 1049516, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "a4c1344872d7e838317a6704b6112bf0775279150dd625cd597473c94d74f39a", "size": 1585096}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-11-08T14:29:14", "last_modified": "2021-11-08T14:31:36", "len_code": 0, "len_context": 1049516, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "15a44677ab22f65cffcd3e9642d020846a922ea739eca7be0bf74876564105bb", "size": 1585904}, {"attribute": "domain", "classification": "UNKNOWN", "file_type": "XLS", "first_seen": "2021-10-15T17:04:21", "last_modified": "2021-10-15T17:14:23", "len_code": 0, "len_context": 0, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "b01e5db107ed26b0db635cf8ead970d7d4fdc267c6bd2047e6e502a773409844", "size": 6922066}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-10-07T17:19:21", "last_modified": "2021-10-07T17:21:25", "len_code": 7933, "len_context": 315935, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "7d2ae2b14c0249d3390fd35869691227f83ca1a2aea9c6cff7f45c27c0c27320", "size": 1709460}, {"attribute": "domain", "classification": "MALICIOUS", "file_type": "XLS", "first_seen": "2021-10-06T11:33:27", "last_modified": "2021-10-06T11:35:36", "len_code": 0, "len_context": 1049203, "len_metadata": 0, "len_ocr": 0, "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "sha256": "6ddae6a0520a9a40d5a5dd7f211f154c34365e4e79404eda78df1c85f1dfed7c", "size": 810230}], "repdb_search": [{"created_date": "2021-07-27T03:10:05", "data": "8.8.8.8", "data_type": "ip", "derived": "15169", "derived_type": "asn_num", "source": "botscout", "source_url": "http://botscout.com"}]}
testing hash...
[2022-01-03T20:32:27.429172] received kind=Hash ioc=bd5acbbfc5c2c8b284ec389207af5759
[2022-01-03T20:32:27.430178] worker-started:dfi_search(['hash', 'md5', 'bd5acbbfc5c2c8b284ec389207af5759'])
[2022-01-03T20:32:27.439961] worker-started:iocdb_search(['bd5acbbfc5c2c8b284ec389207af5759'])
[2022-01-03T20:32:27.440196] waiting up to 30 seconds for 2 jobs to complete....
[2022-01-03T20:32:27.829736] worker-completed:dfi_search(['hash', 'md5', 'bd5acbbfc5c2c8b284ec389207af5759'])
[2022-01-03T20:32:28.429339] worker-completed:iocdb_search(['bd5acbbfc5c2c8b284ec389207af5759'])
[2022-01-03T20:32:28.448783] completed query in 1 seconds.
{"lookup": {"asn": "15169", "asn_cidr": "8.8.8.0/24", "asn_country_code": "US", "asn_date": "1992-12-01", "asn_description": "GOOGLE, US", "asn_registry": "arin"}, "iocdb_search": [{"artifact": "bd5acbbfc5c2c8b284ec389207af5759", "artifact_type": "hash", "created_date": "2021-08-14T15:44:47", "reference_link": "https://research.checkpoint.com/2021/indra-hackers-behind-recent-attacks-on-iran/", "reference_text": "Introduction \n These days, when we think of nation-state level damage, we immediately think of the nation-state level actor that must be res..."}], "dfi_search": [], "repdb_search": [{"created_date": "2021-07-27T03:10:05", "data": "8.8.8.8", "data_type": "ip", "derived": "15169", "derived_type": "asn_num", "source": "botscout", "source_url": "http://botscout.com"}]}
testing url...
[2022-01-03T20:32:28.448949] received kind=URL ioc=http://180.214.239.67/j/p7g/inc/
[2022-01-03T20:32:28.450500] worker-started:dfi_search(['ioc', 'url', 'http://180.214.239.67/j/p7g/inc/'])
[2022-01-03T20:32:28.452248] worker-started:repdb_search(['http://180.214.239.67/j/p7g/inc/'])
[2022-01-03T20:32:28.458846] worker-started:iocdb_search(['http://180.214.239.67/j/p7g/inc/'])
[2022-01-03T20:32:28.459973] waiting up to 30 seconds for 3 jobs to complete....
[2022-01-03T20:32:28.934836] worker-completed:dfi_search(['ioc', 'url', 'http://180.214.239.67/j/p7g/inc/'])
[2022-01-03T20:32:29.467348] worker-completed:iocdb_search(['http://180.214.239.67/j/p7g/inc/'])
[2022-01-03T20:32:33.806322] worker-completed:repdb_search(['http://180.214.239.67/j/p7g/inc/'])
[2022-01-03T20:32:34.001214] completed query in 5 seconds.
{"lookup": {"asn": "15169", "asn_cidr": "8.8.8.0/24", "asn_country_code": "US", "asn_date": "1992-12-01", "asn_description": "GOOGLE, US", "asn_registry": "arin"}, "iocdb_search": [{"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-16T07:16:37", "reference_link": "https://twitter.com/cybersyrupblog/status/1427151826374303745", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-15T21:54:24", "reference_link": "https://twitter.com/MoarGood/status/1427023797106917380", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-15T16:42:04", "reference_link": "https://twitter.com/luc4m/status/1426945766673764365", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-15T16:42:04", "reference_link": "https://twitter.com/Caveman_Cap/status/1426945402117533705", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-15T15:39:34", "reference_link": "https://twitter.com/kilijanek/status/1426927313376190465", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-15T07:19:44", "reference_link": "https://twitter.com/pevma/status/1426797650481979392", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-15T04:12:20", "reference_link": "https://twitter.com/0x4d_/status/1426745967378944004", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-15T03:09:51", "reference_link": "https://twitter.com/A92E/status/1426741770189213700", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-15T02:07:22", "reference_link": "https://twitter.com/_Seyiafro/status/1426711492947230720", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-14T22:59:51", "reference_link": "https://twitter.com/Gi7w0rm/status/1426671118535073792", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-14T21:57:24", "reference_link": "https://twitter.com/ActorExpose/status/1426659328916918273", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-14T21:57:24", "reference_link": "https://twitter.com/Bedrovelsen/status/1426657835862040577", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-14T21:57:24", "reference_link": "https://twitter.com/hasherezade/status/1426657717955989505", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-14T21:57:24", "reference_link": "https://twitter.com/ViriBack/status/1426656595807809537", "reference_text": "RT @jstrosch: #opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}, {"artifact": "http://180.214.239.67/j/p7g/inc/", "artifact_type": "url", "created_date": "2021-08-14T21:57:23", "reference_link": "https://twitter.com/jstrosch/status/1426649722597429248", "reference_text": "#opendir loads of panels :) \n\nhxxp://180.214.239[.]67/j/p7g/inc/ https://t.co/tDMwkBX92d"}], "dfi_search": [], "repdb_search": []}
QED
```
