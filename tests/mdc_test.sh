#! /bin/sh
./mdc_test > result && diff result mdc_test.witness
