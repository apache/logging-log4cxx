#! /bin/sh

./patternlayout_test> result
diff result patternlayout_test.witness
