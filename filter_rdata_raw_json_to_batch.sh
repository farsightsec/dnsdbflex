#! /bin/sh
#
# given json input on stdin from dnsdbflex with the -j option and rdata search, 
# produces batch file output to stdout, as if dnsdbflex
was run with the 
# -R option.
# 
jq -cr '"# rdata/name/"+.rdata+"/"+.rrtype+"\n"+"rdata/raw/"+.raw_rdata+"/"+.rrtype'
