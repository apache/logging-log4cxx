#! /bin/sh
./consoleappender_test > result && diff result consoleappender_test.witness
