#!/bin/bash
# first argument: -v or empty

rm -f Haraka/log/haraka.log Haraka/run/haraka.pid
killall -9 nodejs
killall -9 python
mn -c
echo "" > bft2f.debug
echo bft2f.py $1
python bft2f.py $1
