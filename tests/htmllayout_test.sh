#! /bin/sh

./htmllayout_test> result
cat result | sed 's/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]//' > htmllayout_test.result.stripped
cat htmllayout_test.result.stripped | sed 's/title="[0-9]* thread">[0-9]*<\/td>/title=" thread"><\/td>/' > htmllayout_test.result.stripped2
diff htmllayout_test.result.stripped2 htmllayout_test.witness

