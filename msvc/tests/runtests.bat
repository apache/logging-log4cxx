@echo off

cd ..\..\tests

echo ********** Minimum **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite MinimumTestCase

echo ********** Logger **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite LoggerTestCase

echo ********** PatternLayout **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite PatternLayoutTest

echo ********** HierarchyThreshold **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite HierarchyThresholdTestCase

echo ********** CustomLogger **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite XLoggerTestCase

echo ********** DefaultInit **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite TestCase1
copy input\xml\defaultInit.xml log4j.xml
..\msvc\bin\debug\testsuite TestCase2
del log4j.xml
copy input\defaultInit3.properties log4j.properties
..\msvc\bin\debug\testsuite TestCase3
del log4j.properties
copy input\defaultInit3.properties log4j.properties
copy input\xml\defaultInit.xml log4j.xml
..\msvc\bin\debug\testsuite TestCase4

echo ********** AsyncAppender **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite AsyncAppenderTestCase

echo ********** BoundedFIFO **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite BoundedFIFOTestCase

echo ********** CyclicBuffer **********
call ..\msvc\tests\clean.bat
..\msvc\bin\debug\testsuite CyclicBufferTestCase


cd ..\msvc\tests

