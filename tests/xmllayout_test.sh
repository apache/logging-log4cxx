#! /bin/sh

./xmllayout_test > result
cat result | sed 's/timestamp="[0-9]*"/timestamp=""/' > xmllayout_test.result.stripped
diff xmllayout_test.result.stripped xmllayout_test.witness
