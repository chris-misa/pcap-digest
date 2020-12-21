#!/bin/bash

# Simple parallel batch script

N=6
i=0

IN_PATH="/home/switch_proj/CAIDA/HEADERS_FIVEMINUTE/*.pcap"
OUT_PATH="OUTPUTS"
COMMAND="./main.exe window.all"

for f in $IN_PATH
do
    echo "Starting file $f"
    $COMMAND ${OUT_PATH}/$(echo $f | sed -E "s/.*\/(.+)\.pcap/\1/") $f &
    let i=i+1
    let i=i%N
    [[ $i -eq 0 ]] && echo "Waiting . . ." && wait
done

echo "Waiting for last jobs . . ."
wait

echo "Done."
