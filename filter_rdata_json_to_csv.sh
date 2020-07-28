#! /bin/sh
#
# given json input on stdin from dnsdbflex with the -j option and rdata search, 
# produces batch file output to stdout, as if dnsdbflex was run with the 
# -R option.
# 
echo "rdata,rrtype,time_time,time_last"
jq -cr  '"\""+.rdata+"\","+.rrtype+","+(.time_first|todate)+","+(.time_last|todate)+","'

