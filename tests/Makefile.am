SUBDIRS = input src witness

if TESTS

prepare:
	@if test ! -d "output"; then \
		mkdir output; \
	fi;
	@rm -rf log4j.xml
	@rm -rf log4j.properties
	
build: check-recursive prepare

cleanOutputDir:
	@rm -f output/*
	
check: regression longUnit

regression: Minimum Logger DOM CustomLevel \
	CustomLogger PatternLayout \
	HierarchyThreshold DefaultInit SocketServer \
	XMLLayout AsyncAppender ErrorHandler \
	OptionConverter BoundedFIFO \
	CyclicBuffer VariaLevelMatchFilter \
	VariaLevelRangeFilter PatternParser \
	LevelMatchFilter

longUnit:

Minimum: build cleanOutputDir
	src/testsuite MinimumTestCase
	
Logger: build cleanOutputDir
	src/testsuite LoggerTestCase
	
PatternLayout: build cleanOutputDir
	src/testsuite PatternLayoutTest

HierarchyThreshold: build cleanOutputDir
	src/testsuite HierarchyThresholdTestCase
	
DOM: build cleanOutputDir

CustomLevel: build cleanOutputDir

CustomLogger: build cleanOutputDir
	src/testsuite XLoggerTestCase
	
DefaultInit: build cleanOutputDir
	src/testsuite TestCase1
	@cp input/xml/defaultInit.xml log4j.xml
	src/testsuite TestCase2
	@rm -f log4j.xml
	@cp input/defaultInit3.properties log4j.properties
	src/testsuite TestCase3
	@rm -f log4j.properties
	@cp input/defaultInit3.properties log4j.properties
	@cp input/xml/defaultInit.xml log4j.xml
	src/testsuite TestCase4
	@rm -f log4j.xml
	@rm -f log4j.properties

SocketServer: build cleanOutputDir

XMLLayout: build cleanOutputDir

AsyncAppender: build cleanOutputDir
	src/testsuite AsyncAppenderTestCase

VariaLevelMatchFilter: build cleanOutputDir

VariaLevelRangeFilter: build cleanOutputDir

FiltersLevelMatchFilter: build cleanOutputDir

LevelMatchFilter: build cleanOutputDir

ErrorHandler: build cleanOutputDir

OptionConverter: build cleanOutputDir

BoundedFIFO: build cleanOutputDir
	src/testsuite BoundedFIFOTestCase

CyclicBuffer: build cleanOutputDir

PatternParser: build cleanOutputDir

MazeAppender: build cleanOutputDir

endif
