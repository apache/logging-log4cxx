#! /bin/sh

./patternlayout_test> result
cat result | sed 's/\[[0-9]*\]/\[\]/' > patternlayout_test.result.stripped
diff patternlayout_test.result.stripped patternlayout_test.witness
