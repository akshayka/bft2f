#!/bin/bash
# first argument: -v or empty

killall -9 python
mn -c
echo bft2f.py $1
python bft2f.py $1
