#! /bin/sh
./filter_test > result && diff result filter_test.witness
