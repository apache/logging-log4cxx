#! /bin/sh

./xmllayout_test > result
cat result | sed 's/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]//' > xmllayout_test.result.stripped
diff xmllayout_test.result.stripped xmllayout_test.witness
