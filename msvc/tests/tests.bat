@echo off
if %1/==/ goto usage
if not %1 == debug if not %1 == release if not %1 == unicode_d if not %1 == unicode_r goto usage

..\Bin\%1\hierarchy_test
IF ERRORLEVEL 1 (ECHO hierarchy_test FAILED) ELSE (ECHO hierarchy_test PASSED)

..\Bin\%1\level_test
IF ERRORLEVEL 1 (ECHO level_test FAILED) ELSE (ECHO level_test PASSED)

..\Bin\%1\ndc_test
IF ERRORLEVEL 1 (ECHO ndc_test FAILED) ELSE (ECHO ndc_test PASSED)

..\Bin\%1\mdc_test
IF ERRORLEVEL 1 (ECHO mdc_test FAILED) ELSE (ECHO mdc_test PASSED)

..\Bin\%1\filter_test
IF ERRORLEVEL 1 (ECHO filter_test FAILED) ELSE (ECHO filter_test PASSED)

..\Bin\%1\consoleappender_test
IF ERRORLEVEL 1 (ECHO consoleappender_test FAILED) ELSE (ECHO consoleappender_test PASSED)

..\Bin\%1\fileappender_test
IF ERRORLEVEL 1 (ECHO fileappender_test FAILED) ELSE (ECHO fileappender_test PASSED)

..\Bin\%1\htmllayout_test
IF ERRORLEVEL 1 (ECHO htmllayout_test FAILED) ELSE (ECHO htmllayout_test PASSED)

..\Bin\%1\xmllayout_test
IF ERRORLEVEL 1 (ECHO xmllayout_test FAILED) ELSE (ECHO xmllayout_test PASSED)

..\Bin\%1\ttcclayout_test
IF ERRORLEVEL 1 (ECHO ttcclayout_test FAILED) ELSE (ECHO ttcclayout_test PASSED)

..\Bin\%1\patternlayout_test
IF ERRORLEVEL 1 (ECHO patternlayout_test FAILED) ELSE (ECHO patternlayout_test PASSED)

..\Bin\%1\propertyconfigurator_test ../../tests/propertyconfigurator_test.properties
IF ERRORLEVEL 1 (ECHO propertyconfigurator_test FAILED) ELSE (ECHO propertyconfigurator_test PASSED)

..\Bin\%1\domconfigurator_test ../../tests/domconfigurator_test.xml
IF ERRORLEVEL 1 (ECHO domconfigurator_test FAILED) ELSE (ECHO domconfigurator_test PASSED)

goto done

:usage
echo Usage : tests.bat TARGET 
echo where TARGET can be fixed to debug, release, unicode_d or unicode_r.

:done
