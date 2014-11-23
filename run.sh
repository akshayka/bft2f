#!/bin/bash
# first argument: -v or empty

killall python
mn -c
echo bft2f.py $1
python bft2f.py $1
