#!/usr/bin/python

import os
import sys

if __name__ == '__main__':
    cwd = sys.argv[1]

    # environment variables used by shell and modules
    envvars = {
        'DSHELL': '%s' % (cwd),
        'DECODERPATH': '%s/decoders' % (cwd),
        'BINPATH': '%s/bin' % (cwd),
        'LIBPATH': '%s/lib' % (cwd),
        'DATAPATH': '%s/share' % (cwd),
    }
    # further shell environment setup
    envsetup = {
        'LD_LIBRARY_PATH': '$LIBPATH:$LD_LIBRARY_PATH',
        'PATH': '$BINPATH:$PATH',
        'PYTHONPATH': '$DSHELL:$LIBPATH:$LIBPATH/output:' + os.path.join('$LIBPATH', 'python' + '.'.join(sys.version.split('.', 3)[:2]).split(' ')[0], 'site-packages') + ':$PYTHONPATH'}

    try:
        os.mkdir(os.path.join(
            cwd, 'lib', 'python' + '.'.join(sys.version.split('.', 3)[:2]).split(' ')[0]))
        os.mkdir(os.path.join(cwd, 'lib', 'python' +
                              '.'.join(sys.version.split('.', 3)[:2]).split(' ')[0], 'site-packages'))
    except Exception, e:
        print e

    envdict = {}
    envdict.update(envvars)
    envdict.update(envsetup)

    #.dshellrc text
    env = ['export PS1="`whoami`@`hostname`:\w Dshell> "'] + ['export %s=%s' %
                                                              (k, v) for k, v in envvars.items()] + ['export %s=%s' % (k, v) for k, v in envsetup.items()]
    outfd = open('.dshellrc', 'w')
    outfd.write("\n".join(env))
    if len(sys.argv) > 2 and sys.argv[2] == 'with_bash_completion':
        outfd.write('''


if [ `echo $BASH_VERSION | cut -d'.' -f1` -ge '4' ]; then
if [ -f ~/.bash_aliases ]; then
. ~/.bash_aliases
fi

if [ -f /etc/bash_completion ]; then
. /etc/bash_completion
fi

find_decoder()
{
local IFS="+"
for (( i=0; i<${#COMP_WORDS[@]}; i++ ));
do
   if [ "${COMP_WORDS[$i]}" == '-d' ] ; then
        decoders=(${COMP_WORDS[$i+1]})
   fi
done
}

get_decoders()
{
   decoders=$(for x in `find $DECODERPATH -iname '*.py' | grep -v '__init__'`; do basename ${x} .py; done)
}

_decode()
{
local dashdashcommands=' --ebpf --output --outfile --logfile'

local cur prev xspec decoders
COMPREPLY=()
cur=`_get_cword`
_expand || return 0
prev="${COMP_WORDS[COMP_CWORD-1]}"

case "${cur}" in
--*)
    find_decoder
    local options=""
#           if [ -n "$decoders" ]; then
#               for decoder in "${decoders[@]}"
#               do
#                 options+=`/usr/bin/python $BINPATH/gen_decoder_options.py $decoder`
#                 options+=" "
#               done
#           fi

    options+=$dashdashcommands
    COMPREPLY=( $(compgen -W "${options}" -- ${cur}) )
    return 0
    ;;

*+*)
   get_decoders
   firstdecoder=${cur%+*}"+"
   COMPREPLY=( $(compgen -W "${decoders}" -P $firstdecoder -- ${cur//*+}) )
   return 0
   ;;

esac

xspec="*.@(cap|pcap)"
xspec="!"$xspec
case "${prev}" in
-d)
   get_decoders
   COMPREPLY=( $(compgen -W "${decoders[0]}" -- ${cur}) )
   return 0
   ;;

--output)
   local outputs=$(for x in `find $DSHELL/lib/output -iname '*.py' | grep -v 'output.py'`; do basename ${x} .py; done)

   COMPREPLY=( $(compgen -W "${outputs}" -- ${cur}) )
   return 0
   ;;

-F | -o | --outfile | -L | --logfile)
   xspec=
   ;;

esac

COMPREPLY=( $( compgen -f -X "$xspec" -- "$cur" ) \
$( compgen -d -- "$cur" ) )
}
complete -F _decode -o filenames decode
complete -F _decode -o filenames decode.py
fi
''')
    outfd.close()

    # dshell text
    outfd = open('dshell', 'w')
    outfd.write('#!/bin/bash\n')
    outfd.write('/bin/bash --rcfile %s/.dshellrc\n' % (cwd))
    outfd.close()

    # dshell-decode text
    outfd = open('dshell-decode', 'w')
    outfd.write('#!/bin/bash\n')
    outfd.write('source %s/.dshellrc\n' % (cwd))
    outfd.write('decode "$@"')
    outfd.close()
