#! /bin/sh

./htmlappender_test > result
cat result | sed 's/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]//' > htmlappender_test.result.stripped
diff htmlappender_test.result.stripped htmlappender_test.witness
