#! /bin/sh

./ttcclayout_test> result
diff result ttcclayout_test.witness
