#! /bin/sh

./ttcclayout_test> result
cat result | sed 's/\[[0-9]*\]/\[\]/' > ttcclayout_test.result.stripped
diff ttcclayout_test.result.stripped ttcclayout_test.witness
