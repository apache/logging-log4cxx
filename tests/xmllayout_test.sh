#! /bin/sh

./xmllayout_test > result
cat result | sed 's/timestamp="[0-9]*"/timestamp=""/' > xmllayout_test.result.stripped
cat xmllayout_test.result.stripped | sed 's/thread="[0-9]*">/thread="">/' > xmllayout_test.result.stripped2
diff xmllayout_test.result.stripped2 xmllayout_test.witness
