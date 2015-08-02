#!/bin/sh

includes="./"

libs="-lpthread"

objs="pd_socket
      pd_log
      pd_define
      pd_event
      pd_ioc
      pd_tcp
      pd_accepter
      pd_transport
      pd_ringbuffer
      pd_udp_server
     "

mains="
       client
       server
       userver
       uclient
       nat_server
       nat_peer_server
      "

opt=""
opt="$opt -O3"

##########
compile()
{
  echo $@
  `$@`
  if [ $? -ne 0 ]
  then
    exit -1
  fi
}

##########
modules=""
for o in $objs
do
  compile "gcc -g $opt -c $o.c -I $includes"
  modules=`echo $modules $o.o`
done

##########
for m in $mains
do
  compile "gcc -g $opt -c $m.c -I $includes"
  compile "gcc -g $opt -o $m $m.o $modules $libs"
done

