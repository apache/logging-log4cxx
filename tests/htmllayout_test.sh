#! /bin/sh

./htmllayout_test> result
cat result | sed 's/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]//' > htmllayout_test.result.stripped
diff htmllayout_test.result.stripped htmllayout_test.witness
