#! /bin/sh
./hierarchy_test > result && diff result hierarchy_test.witness
