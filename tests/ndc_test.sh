#! /bin/sh
./ndc_test > result && diff result ndc_test.witness
