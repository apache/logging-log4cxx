#! /bin/sh
./level_test > result && diff result level_test.witness
