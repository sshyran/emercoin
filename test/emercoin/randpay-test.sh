#!/bin/sh -v
echo 'Randpay test started'

# 1st step: create challenge with risk=3 (probability=1/3) and 1000s timeout
CHAP=`emc randpay_createaddrchap 3 1000`

# 2nd step: create RandpayTX for 0.5EMC, chapaddr=got_above, risk=3, 1000s timeout, non-naive
TX=`emc randpay_createtx 0.5 $CHAP 3 10000`

# 3rd step: submit to the wallet the RandpayTX(got in 2), with risk=3
emc randpay_submittx $TX 3

