#!/bin/bash

d=$(pwd)
[ "$1" ] && d="$1"
source $d/.dshellrc || exit

for f in $d/lib/*.py $d/lib/output/*.py $d/bin/*.py; do 
    pydoc -w $(basename $f | cut -d. -f1)
done

for f in $(find $d/decoders -name \*.py -not -name __init__.py); do
    pydoc -w $f 
done
