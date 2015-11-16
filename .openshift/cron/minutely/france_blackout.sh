#!/bin/bash
dt=$(date '+%Y-%m-%d %H:%M')
# echo $dt
if [ "$dt" != "2015-11-16 06:00" ] && [ "$dt" != "2015-11-16 06:05" ] ; then
    echo "not time yet: $dt"
    exit
fi
# rest of the script
echo python3 ~/french_blackout.py