# Microsoft Developer Studio Project File - Name="dll" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=dll - Win32 Unicode Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "dll.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "dll.mak" CFG="dll - Win32 Unicode Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "dll - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "dll - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "dll - Win32 Unicode Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "dll - Win32 Unicode Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "dll - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "DLL_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W3 /GX /Zi /O2 /I "../../include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "DLL_EXPORTS" /D "LOG4CXX" /FD /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 advapi32.lib Ws2_32.lib odbc32.lib /nologo /dll /pdb:"../Bin/Release/log4cxx.pdb" /debug /machine:I386 /out:"../Bin/Release/log4cxx.dll" /implib:"../Lib/Release/log4cxx.lib"
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "dll - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "DLL_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "../../include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "DLL_EXPORTS" /D "LOG4CXX" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 advapi32.lib Ws2_32.lib odbc32.lib /nologo /dll /pdb:"../Bin/Debug/log4cxx.pdb" /map /debug /machine:I386 /out:"../Bin/Debug/log4cxx.dll" /implib:"../Lib/Debug/log4cxx.lib" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "dll - Win32 Unicode Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "dll___Win32_Unicode_Debug"
# PROP BASE Intermediate_Dir "dll___Win32_Unicode_Debug"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Unicode_D"
# PROP Intermediate_Dir "Unicode_D"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "../../include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "DLL_EXPORTS" /D "LOG4CXX" /FR /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "../../include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "DLL_EXPORTS" /D "LOG4CXX" /D "UNICODE" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 advapi32.lib Ws2_32.lib /nologo /dll /pdb:"../Bin/Debug/log4cxx.pdb" /map /debug /machine:I386 /out:"../Bin/Debug/log4cxx.dll" /implib:"../Lib/Debug/log4cxx.lib" /pdbtype:sept
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 advapi32.lib Ws2_32.lib odbc32.lib /nologo /dll /pdb:"../Bin/Unicode_D/log4cxx.pdb" /map /debug /machine:I386 /out:"../Bin/Unicode_D/log4cxx.dll" /implib:"../Lib/Unicode_D/log4cxx.lib" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "dll - Win32 Unicode Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "dll___Win32_Unicode_Release"
# PROP BASE Intermediate_Dir "dll___Win32_Unicode_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Unicode_R"
# PROP Intermediate_Dir "Unicode_R"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /Zi /O2 /I "../../include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "DLL_EXPORTS" /D "LOG4CXX" /FD /c
# SUBTRACT BASE CPP /YX /Yc /Yu
# ADD CPP /nologo /MD /W3 /GX /Zi /O2 /I "../../include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "DLL_EXPORTS" /D "LOG4CXX" /D "UNICODE" /FD /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 advapi32.lib Ws2_32.lib /nologo /dll /pdb:"../Bin/Release/log4cxx.pdb" /debug /machine:I386 /out:"../Bin/Release/log4cxx.dll" /implib:"../Lib/Release/log4cxx.lib"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 advapi32.lib Ws2_32.lib odbc32.lib /nologo /dll /pdb:"../Bin/Unicode_R/log4cxx.pdb" /debug /machine:I386 /out:"../Bin/Unicode_R/log4cxx.dll" /implib:"../Lib/Unicode_R/log4cxx.lib"
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "dll - Win32 Release"
# Name "dll - Win32 Debug"
# Name "dll - Win32 Unicode Debug"
# Name "dll - Win32 Unicode Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\src\appenderattachableimpl.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\appenderskeleton.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\asyncappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\basicconfigurator.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\boundedfifo.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\class.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\condition.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\configurator.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\consoleappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\criticalsection.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\cyclicbuffer.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\datagrampacket.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\datagramsocket.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\dateformat.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\datelayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\defaultcategoryfactory.cpp
# End Source File
# Begin Source File

SOURCE=.\dll.cpp

!IF  "$(CFG)" == "dll - Win32 Release"

!ELSEIF  "$(CFG)" == "dll - Win32 Debug"

# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "dll - Win32 Unicode Debug"

# ADD BASE CPP /w /W0
# ADD CPP /w /W0

!ELSEIF  "$(CFG)" == "dll - Win32 Unicode Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\src\domconfigurator.cpp
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\nt\EventLogCategories.mc

!IF  "$(CFG)" == "dll - Win32 Release"

# Begin Custom Build - Compiling EventLog message file
IntDir=.\Release
TargetDir=\log4cxx-0.9.4\msvc\Bin\Release
InputPath=..\..\include\log4cxx\nt\EventLogCategories.mc

BuildCmds= \
	MC $(InputPath) -r $(IntDir) \
	RC -r -fo $(IntDir)\EventLogCategories.res $(IntDir)\EventLogCategories.rc \
	LINK /subsystem:windows /INCREMENTAL:NO /dll /out:$(TargetDir)\NTEventLogAppender.dll /NOENTRY /machine:I386 $(IntDir)\EventLogCategories.res \
	

"$(IntDir)\EventLogCategories.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(IntDir)\EventLogCategories.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(TargetDir)\NTEventLogAppender.dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "dll - Win32 Debug"

# Begin Custom Build - Compiling EventLog message file
IntDir=.\Debug
TargetDir=\log4cxx-0.9.4\msvc\Bin\Debug
InputPath=..\..\include\log4cxx\nt\EventLogCategories.mc

BuildCmds= \
	MC $(InputPath) -r $(IntDir)  -h $(IntDir) \
	RC -r -fo $(IntDir)\EventLogCategories.res $(IntDir)\EventLogCategories.rc \
	LINK /subsystem:windows /INCREMENTAL:NO /dll /out:$(TargetDir)\NTEventLogAppender.dll /NOENTRY /machine:I386 $(IntDir)\EventLogCategories.res \
	

"$(IntDir)\EventLogCategories.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(IntDir)\EventLogCategories.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(TargetDir)\NTEventLogAppender.dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "dll - Win32 Unicode Debug"

# Begin Custom Build - Compiling EventLog message file
IntDir=.\Unicode_D
TargetDir=\log4cxx-0.9.4\msvc\Bin\Unicode_D
InputPath=..\..\include\log4cxx\nt\EventLogCategories.mc

BuildCmds= \
	MC $(InputPath) -r $(IntDir)  -h $(IntDir) \
	RC -r -fo $(IntDir)\EventLogCategories.res $(IntDir)\EventLogCategories.rc \
	LINK /subsystem:windows /INCREMENTAL:NO /dll /out:$(TargetDir)\NTEventLogAppender.dll /NOENTRY /machine:I386 $(IntDir)\EventLogCategories.res \
	

"$(IntDir)\EventLogCategories.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(IntDir)\EventLogCategories.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(TargetDir)\NTEventLogAppender.dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "dll - Win32 Unicode Release"

# Begin Custom Build - Compiling EventLog message file
IntDir=.\Unicode_R
TargetDir=\log4cxx-0.9.4\msvc\Bin\Unicode_R
InputPath=..\..\include\log4cxx\nt\EventLogCategories.mc

BuildCmds= \
	MC $(InputPath) -r $(IntDir) \
	RC -r -fo $(IntDir)\EventLogCategories.res $(IntDir)\EventLogCategories.rc \
	LINK /subsystem:windows /INCREMENTAL:NO /dll /out:$(TargetDir)\NTEventLogAppender.dll /NOENTRY /machine:I386 $(IntDir)\EventLogCategories.res \
	

"$(IntDir)\EventLogCategories.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(IntDir)\EventLogCategories.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(TargetDir)\NTEventLogAppender.dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\src\fileappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\filewatchdog.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\formattinginfo.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\hierarchy.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\htmllayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\inetaddress.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\layout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\level.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\levelmatchfilter.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\levelrangefilter.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\loader.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\logger.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\loggingevent.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\loglog.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\logmanager.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\mdc.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\msxml.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\mutex.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\ndc.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\nteventlogappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\objectimpl.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\odbcappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\onlyonceerrorhandler.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\optionconverter.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\patternconverter.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\patternlayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\patternparser.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\properties.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\propertyconfigurator.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\propertysetter.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\rollingfileappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\rootcategory.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\semaphore.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\serversocket.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\simplelayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\simplesocketserver.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\smtpappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\socket.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\socketappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\sockethubappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\socketimpl.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\socketinputstream.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\socketnode.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\socketoutputstream.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\stringmatchfilter.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\stringtokenizer.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\syslogappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\syslogwriter.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\system.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\telnetappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\thread.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\threadspecificdata.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\transform.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\ttcclayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\writerappender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\xmllayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\xmlsocketappender.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Group "helpers"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\absolutetimedateformat.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\appenderattachableimpl.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\boundedfifo.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\class.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\condition.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\criticalsection.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\cyclicbuffer.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\datagrampacket.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\datagramsocket.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\dateformat.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\datelayout.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\datetimedateformat.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\exception.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\filewatchdog.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\formattinginfo.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\gnomexml.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\inetaddress.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\iso8601dateformat.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\loader.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\loglog.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\msxml.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\mutex.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\object.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\objectimpl.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\objectptr.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\onlyonceerrorhandler.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\optionconverter.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\patternconverter.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\patternparser.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\properties.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\relativetimedateformat.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\semaphore.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\serversocket.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\socket.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\socketimpl.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\socketinputstream.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\socketoutputstream.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\stringhelper.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\stringtokenizer.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\syslogwriter.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\system.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\tchar.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\thread.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\threadspecificdata.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\transform.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\helpers\xml.h
# End Source File
# End Group
# Begin Group "spi"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\appenderattachable.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\configurator.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\defaultrepositoryselector.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\errorhandler.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\filter.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\hierarchyeventlistener.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\loggerfactory.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\loggerrepository.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\loggingevent.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\optionhandler.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\repositoryselector.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\rootcategory.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\spi\triggeringeventevaluator.h
# End Source File
# End Group
# Begin Group "xml"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=..\..\include\log4cxx\xml\domconfigurator.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\xml\xmllayout.h
# End Source File
# End Group
# Begin Group "net"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=..\..\include\log4cxx\net\smtpappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\net\socketappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\net\sockethubappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\net\socketnode.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\net\syslogappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\net\telnetappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\net\xmlsocketappender.h
# End Source File
# End Group
# Begin Group "varia"

# PROP Default_Filter "*"
# Begin Source File

SOURCE=..\..\include\log4cxx\varia\denyallfilter.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\varia\levelmatchfilter.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\varia\levelrangefilter.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\varia\stringmatchfilter.h
# End Source File
# End Group
# Begin Group "nt"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=..\..\include\log4cxx\nt\nteventlogappender.h
# End Source File
# End Group
# Begin Group "config"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=..\..\include\log4cxx\config\propertysetter.h
# End Source File
# End Group
# Begin Group "db"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=..\..\include\log4cxx\db\odbcappender.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\include\log4cxx\appender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\appenderskeleton.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\asyncappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\basicconfigurator.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\config.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\consoleappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\defaultcategoryfactory.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\fileappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\hierarchy.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\htmllayout.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\layout.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\level.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\logger.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\logmanager.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\mdc.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\ndc.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\patternlayout.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\propertyconfigurator.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\provisionnode.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\rollingfileappender.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\simplelayout.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\ttcclayout.h
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cxx\writerappender.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
