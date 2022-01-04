#!/bin/sh

cp README.md README.TXT
tar zcvf rfiq_extension.tgz README.TXT docopt.py extension.json inquestlabs.py iq_full.png iq_thumbnail.png metadata.json requests/ rfiq-card.py
rm -f README.TXT
