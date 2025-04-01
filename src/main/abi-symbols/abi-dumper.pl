#!/usr/bin/perl
###########################################################################
# ABI Dumper 1.3
# Dump ABI of an ELF object containing DWARF debug info
#
# Copyright (C) 2013-2025 Andrey Ponomarenko's ABI Laboratory
#
# Written by Andrey Ponomarenko
#
# PLATFORMS
# =========
#  Linux
#
# REQUIREMENTS
# ============
#  Perl 5 (5.8 or newer)
#  Elfutils (eu-readelf)
#  GNU Binutils (objdump)
#  Vtable-Dumper (1.1 or newer)
#  Universal Ctags
#  GCC C++
#
# COMPATIBILITY
# =============
#  ABI Viewer >= 1.0
#  ABI Compliance Checker >= 2.2
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301 USA
###########################################################################
use Getopt::Long;
Getopt::Long::Configure ("posix_default", "no_ignore_case", "permute");
use File::Path qw(mkpath rmtree);
use File::Temp qw(tempdir);
use Cwd qw(abs_path cwd realpath);
use Storable qw(dclone);
use Data::Dumper;

my $TOOL_VERSION = "1.4";
my $ABI_DUMP_VERSION = "3.5";
my $ORIG_DIR = cwd();
my $TMP_DIR = tempdir(CLEANUP=>1);

my $VTABLE_DUMPER = "vtable-dumper";
my $VTABLE_DUMPER_VERSION = "1.0";

my $LOCALE = "LANG=C.UTF-8";
my $EU_READELF = "eu-readelf";
my $EU_READELF_L = $LOCALE." ".$EU_READELF;
my $OBJDUMP = "objdump";
my $CTAGS = "ctags";
my $EXUBERANT_CTAGS = 0;
my $GPP = "g++";

my ($Help, $ShowVersion, $DumpVersion, $OutputDump, $SortDump, $StdOut,
$TargetVersion, $ExtraInfo, $FullDump, $AllTypes, $AllSymbols, $BinOnly,
$SkipCxx, $Loud, $AddrToName, $DumpStatic, $Compare, $AltDebugInfoOpt,
$AddDirs, $VTDumperPath, $SymbolsListPath, $PublicHeadersPath,
$IgnoreTagsPath, @CtagsDef, $KernelExport, $UseTU, $ReimplementStd,
$IncludePreamble, $IncludePaths, $CacheHeaders, $MixedHeaders, $Debug,
$SearchDirDebuginfo, $KeepRegsAndOffsets, $Quiet, $IncludeDefines,
$AllUnits, $LambdaSupport, $LdLibraryPath, $ExtraDump);

my $CmdName = getFilename($0);

my %ERROR_CODE = (
    "Success"=>0,
    "Error"=>2,
    # System command is not found
    "Not_Found"=>3,
    # Cannot access input files
    "Access_Error"=>4,
    # Cannot find a module
    "Module_Error"=>9,
    # No debug-info
    "No_DWARF"=>10,
    # Invalid debug-info
    "Invalid_DWARF"=>11,
    # No exported symbols
    "No_Exported"=>12
);

my $ShortUsage = "ABI Dumper $TOOL_VERSION EE
Dump ABI of an ELF object containing DWARF debug info
Copyright (C) 2025 Andrey Ponomarenko's ABI Laboratory
License: GNU LGPL 2.1

Usage: $CmdName [options] [object]
Example:
  $CmdName libTest.so -o ABI.dump
  $CmdName Module.ko.debug -o ABI.dump

More info: $CmdName --help\n";

if($#ARGV==-1)
{
    printMsg("INFO", $ShortUsage);
    exit(0);
}

GetOptions("h|help!" => \$Help,
  "v|version!" => \$ShowVersion,
  "dumpversion!" => \$DumpVersion,
# general options
  "o|output|dump-path=s" => \$OutputDump,
  "sort!" => \$SortDump,
  "stdout!" => \$StdOut,
  "loud!" => \$Loud,
  "vnum|lver|lv=s" => \$TargetVersion,
  "extra-info=s" => \$ExtraInfo,
  "bin-only!" => \$BinOnly,
  "all-types!" => \$AllTypes,
  "all-symbols!" => \$AllSymbols,
  "symbols-list=s" => \$SymbolsListPath,
  "skip-cxx!" => \$SkipCxx,
  "all!" => \$FullDump,
  "dump-static!" => \$DumpStatic,
  "compare!" => \$Compare,
  "alt=s" => \$AltDebugInfoOpt,
  "dir!" => \$AddDirs,
  "vt-dumper=s" => \$VTDumperPath,
  "public-headers=s" => \$PublicHeadersPath,
  "ignore-tags=s" => \$IgnoreTagsPath,
  "ctags-def=s" => \@CtagsDef,
  "mixed-headers!" => \$MixedHeaders,
  "kernel-export!" => \$KernelExport,
  "search-debuginfo=s" => \$SearchDirDebuginfo,
  "keep-registers-and-offsets!" => \$KeepRegsAndOffsets,
  "all-units!" => \$AllUnits,
  "quiet!" => \$Quiet,
  "debug!" => \$Debug,
# extra options
  "use-tu-dump!" => \$UseTU,
  "include-preamble=s" => \$IncludePreamble,
  "include-paths=s" => \$IncludePaths,
  "include-defines=s" => \$IncludeDefines,
  "cache-headers=s" => \$CacheHeaders,
  "lambda!" => \$LambdaSupport,
  "ld-library-path=s" => \$LdLibraryPath,
# internal options
  "addr2name!" => \$AddrToName,
  "extra-dump!" => \$ExtraDump,
# obsolete
  "reimplement-std!" => \$ReimplementStd
) or errMsg();

sub errMsg()
{
    printMsg("INFO", "\n".$ShortUsage);
    exit($ERROR_CODE{"Error"});
}

my $HelpMessage="
NAME:
  ABI Dumper EE ($CmdName)
  Dump ABI of an ELF object containing DWARF debug info

DESCRIPTION:
  ABI Dumper is a tool for dumping ABI information of an ELF object
  containing DWARF debug info.
  
  The tool is intended to be used with ABI Viewer or ABICC tool for
  tracking ABI changes of a C/C++ library or kernel module.

  This tool is free software: you can redistribute it and/or modify it
  under the terms of the GNU LGPL 2.1.

USAGE:
  $CmdName [options] [object]

EXAMPLES:
  $CmdName libTest.so -o ABI.dump
  $CmdName Module.ko.debug -o ABI.dump

INFORMATION OPTIONS:
  -h|-help
      Print this help.

  -v|-version
      Print version information.

  -dumpversion
      Print the tool version ($TOOL_VERSION) and don't do anything else.

GENERAL OPTIONS:
  -o|-output PATH
      Path to the output ABI dump file.
      Default: ./ABI.dump
      
  -sort
      Sort data in ABI dump.
      
  -stdout
      Print ABI dump to stdout.
      
  -loud
      Print all warnings.
      
  -vnum NUM
      Set version of the library to NUM.
      
  -extra-info DIR
      Dump extra analysis info to DIR.
      
  -bin-only
      Do not dump information about inline functions,
      pure virtual functions and non-exported global data.
      
  -all-types
      Dump unused data types.
      
  -all-symbols
      Dump symbols not exported by the object.
      
  -symbols-list PATH
      Specify a file with a list of symbols that should be dumped.
      
  -skip-cxx
      Do not dump stdc++ and gnu c++ symbols.
      
  -all
      Equal to: -all-types -all-symbols.
      
  -dump-static
      Dump static (local) symbols.
      
  -compare OLD.dump NEW.dump
      Show added/removed symbols between two ABI dumps.
      
  -alt PATH
      Path to the alternate debug info (Fedora). It is
      detected automatically from gnu_debugaltlink section
      of the input object if not specified.
      
  -dir
      Show full paths of source files.
  
  -vt-dumper PATH
      Path to the vtable-dumper executable if it is installed
      to non-default location (not in PATH).
  
  -public-headers PATH
      Path to directory with public header files or to file with
      the list of header files. This option allows to filter out
      private symbols from the ABI dump.
  
  -ignore-tags PATH
      Path to ignore.tags file to help ctags tool to read
      symbols in header files.
  
  -ctags-def DEF
      Add -D DEF option to the ctags call. This option may be
      specified multiple times.
  
  -reimplement-std
      Do nothing.
  
  -mixed-headers
      This option should be specified if you are using
      -public-headers option and the names of public headers
      intersect with the internal headers.
  
  -kernel-export
      Dump symbols exported by the Linux kernel and modules, i.e.
      symbols declared in the ksymtab section of the object and
      system calls.
  
  -search-debuginfo DIR
      Search for debug-info files referenced from gnu_debuglink
      section of the object in DIR.
  
  -keep-registers-and-offsets
      Dump used registers and stack offsets even if incompatible
      build options detected.
  
  -all-units
      Extract ABI info after reading all compilation units from
      the debug info. This may require a lot of extra RAM memory.
      By default all compilation units are processed separately.
  
  -quiet
      Do not warn about incompatible build options.
  
  -debug
      Enable debug messages.

EXTRA OPTIONS:
  -use-tu-dump
      Use g++ -fdump-translation-unit instead of ctags to
      list symbols in headers. This may be useful if all
      functions are declared via macros in headers and
      ctags can't recognize them.
  
  -include-preamble PATHS
      Specify header files (separated by semicolon) that
      should be included before others to compile without
      errors.
  
  -include-paths DIRS
      Specify include directories (separated by semicolon)
      that should be passed to the compiler by -I option
      in order to compile headers without errors. If this
      option is not set then the tool will try to generate
      include paths automatically.
  
  -cache-headers DIR
      Cache headers analysis results to reuse later.
  
  -lambda
      Enable support for lambda and checking of lexical
      blocks. Define it if your C++ library API functions
      use lambda expressions.
  
  -ld-library-path PATHS
      Specify paths to add to LD_LIBRARY_PATH variable before
      executing vtable-dumper (separated by colon).
      
      By default lexical blocks are not analyzed to
      improve performance.
";

sub helpMsg() {
    printMsg("INFO", $HelpMessage);
}

my %Cache;

# Input
my %DWARF_Info;
my @IDs;

# Alternate
my @IDs_I;
my $AltDebugInfo = undef;
my $TooBig = 0;

my $Compressed = undef;
my $Partial = undef;

# Dump
my %TypeUnit;
my %Post_Change;

# Output
my %TypeInfo;
my %SymbolInfo;

# Other
my $TargetName = undef;
my %NestedNameSpaces;
my %HeadersInfo;
my %SourcesInfo;
my %SymVer;
my %LexicalId;

# Reader (per compile unit)
my %TypeMember;
my %ArrayCount;
my %FuncParam;
my %TmplParam;
my %Inheritance;
my %NameSpace;
my %SpecElem;
my %OrigElem;
my %ClassMethods;

# Reader
my %TypeSpec;
my %ClassChild;
my %SourceFile;
my %SourceFile_Alt;
my %DebugLoc;
my %TName_Tid;
my %TName_Tids;
my %RegName;

my $STDCXX_TARGET = 0;
my $GLOBAL_ID = 0;
my %ANON_TYPE_WARN = ();

my %Mangled_ID;
my %Checked_Spec;
my %SelectedSymbols;

# Cleaning
my %MergedTypes;
my %LocalType;
my %UsedType;
my %DeletedAnon;
my %CheckedType;
my %DuplBaseType;

# Language
my %TypeType = (
    "class_type"=>"Class",
    "structure_type"=>"Struct",
    "union_type"=>"Union",
    "enumeration_type"=>"Enum",
    "subroutine_type"=>"Func",
    "array_type"=>"Array",
    "base_type"=>"Intrinsic",
    "atomic_type"=>"Intrinsic",
    "unspecified_type"=>"Unspecified",
    "const_type"=>"Const",
    "pointer_type"=>"Pointer",
    "reference_type"=>"Ref",
    "rvalue_reference_type"=>"RvalueRef",
    "volatile_type"=>"Volatile",
    "restrict_type"=>"Restrict",
    "typedef"=>"Typedef",
    "ptr_to_member_type"=>"FieldPtr",
    "string_type"=>"String"
);

my %Qual = (
    "Pointer"=>"*",
    "Ref"=>"&",
    "RvalueRef"=>"&&",
    "Volatile"=>"volatile",
    "Restrict"=>"restrict",
    "Const"=>"const"
);

my %ConstSuffix = (
    "unsigned int" => "u",
    "unsigned long" => "ul",
    "unsigned long long" => "ull",
    "long" => "l",
    "long long" => "ll"
);

my $HEADER_EXT = "h|hh|hp|hxx|hpp|h\\+\\+|tcc|txx|x|inl|inc|ads|isph";
my $SRC_EXT = "c|cc|cp|cpp|cxx|c\\+\\+";

# ELF
my %Library_Symbol;
my %Library_UndefSymbol;
my %Library_Needed;
my %SymbolTable;
my %Symbol_Bind;

# Extra Dump
my %SymbolAttribute;
my $GLOBAL_ID_T = 0;
my %FullLoc = ();

# Kernel
my %KSymTab;

# VTables
my %VirtualTable;
my %VTable_Symbol;
my %VTable_Class;

# Env
my $SYS_ARCH;
my $SYS_WORD;
my $SYS_GCCV;
my $SYS_CLANGV = undef;
my $SYS_COMP;
my $LIB_LANG;
my $OBJ_LANG;

# Errors
my $InvalidDebugLoc;
my $IncompatibleOpt = undef;
my $FKeepInLine = undef;

# Public Headers
my %SymbolToHeader;
my %TypeToHeader;
my %PublicHeader;
my $PublicSymbols_Detected;
my $PublicHeadersIsDir = 1;

# Filter
my %SymbolsList;

# Dump
my $COMPRESS = "tar.gz";

sub printMsg($$)
{
    my ($Type, $Msg) = @_;
    if($Type!~/\AINFO/) {
        $Msg = $Type.": ".$Msg;
    }
    if($Type!~/_C\Z/) {
        $Msg .= "\n";
    }
    if($Type eq "ERROR"
    or $Type eq "WARNING") {
        print STDERR $Msg;
    }
    else {
        print $Msg;
    }
}

sub exitStatus($$)
{
    my ($Code, $Msg) = @_;
    printMsg("ERROR", $Msg);
    exit($ERROR_CODE{$Code});
}

sub cmpVersions($$)
{ # compare two versions in dotted-numeric format
    my ($V1, $V2) = @_;
    return 0 if($V1 eq $V2);
    return undef if($V1!~/\A\d+[\.\d+]*\Z/);
    return undef if($V2!~/\A\d+[\.\d+]*\Z/);
    my @V1Parts = split(/\./, $V1);
    my @V2Parts = split(/\./, $V2);
    for (my $i = 0; $i <= $#V1Parts && $i <= $#V2Parts; $i++) {
        return -1 if(int($V1Parts[$i]) < int($V2Parts[$i]));
        return 1 if(int($V1Parts[$i]) > int($V2Parts[$i]));
    }
    return -1 if($#V1Parts < $#V2Parts);
    return 1 if($#V1Parts > $#V2Parts);
    return 0;
}

sub writeFile($$)
{
    my ($Path, $Content) = @_;
    
    if(my $Dir = getDirname($Path)) {
        mkpath($Dir);
    }
    open(FILE, ">", $Path) || die ("can't open file \'$Path\': $!\n");
    print FILE $Content;
    close(FILE);
}

sub readFile($)
{
    my $Path = $_[0];
    
    open(FILE, $Path);
    local $/ = undef;
    my $Content = <FILE>;
    close(FILE);
    return $Content;
}

sub getFilename($)
{ # much faster than basename() from File::Basename module
    if($_[0] and $_[0]=~/([^\/\\]+)[\/\\]*\Z/) {
        return $1;
    }
    return "";
}

sub getDirname($)
{ # much faster than dirname() from File::Basename module
    if($_[0] and $_[0]=~/\A(.*?)[\/\\]+[^\/\\]*[\/\\]*\Z/) {
        return $1;
    }
    return "";
}

sub sepPath($) {
    return (getDirname($_[0]), getFilename($_[0]));
}

sub checkCmd($)
{
    my $Cmd = $_[0];
    
    if(defined $Cache{"checkCmd"}{$Cmd}) {
        return $Cache{"checkCmd"}{$Cmd};
    }
    
    if(-x $Cmd)
    { # relative or absolute path
        return ($Cache{"checkCmd"}{$Cmd} = 1);
    }
    
    foreach my $Path (sort {length($a)<=>length($b)} split(/:/, $ENV{"PATH"}))
    {
        if(-x $Path."/".$Cmd) {
            return ($Cache{"checkCmd"}{$Cmd} = 1);
        }
    }
    return ($Cache{"checkCmd"}{$Cmd} = 0);
}

my %ELF_BIND = map {$_=>1} (
    "WEAK",
    "GLOBAL",
    "LOCAL"
);

my %ELF_TYPE = map {$_=>1} (
    "FUNC",
    "IFUNC",
    "GNU_IFUNC",
    "TLS",
    "OBJECT",
    "COMMON"
);

my %ELF_VIS = map {$_=>1} (
    "DEFAULT",
    "PROTECTED"
);

sub readline_ELF($)
{ # read the line of 'eu-readelf' output corresponding to the symbol
    my @Info = split(/\s+/, $_[0]);
    #  Num:   Value      Size Type   Bind   Vis       Ndx  Name
    #  3629:  000b09c0   32   FUNC   GLOBAL DEFAULT   13   _ZNSt12__basic_fileIcED1Ev@@GLIBCXX_3.4
    #  135:   00000000    0   FUNC   GLOBAL DEFAULT   UNDEF  av_image_fill_pointers@LIBAVUTIL_52 (3)
    shift(@Info) if($Info[0] eq ""); # spaces
    shift(@Info); # num
    
    if($#Info==7)
    { # UNDEF SYMBOL (N)
        if($Info[7]=~/\(\d+\)/) {
            pop(@Info);
        }
    }
    
    if($#Info!=6)
    { # other lines
        return ();
    }
    return () if(not defined $ELF_TYPE{$Info[2]} and $Info[5] ne "UNDEF");
    return () if(not defined $ELF_BIND{$Info[3]});
    return () if(not defined $ELF_VIS{$Info[4]});
    if($Info[5] eq "ABS" and $Info[0]=~/\A0+\Z/)
    { # 1272: 00000000     0 OBJECT  GLOBAL DEFAULT  ABS CXXABI_1.3
        return ();
    }
    if(index($Info[2], "0x") == 0)
    { # size == 0x3d158
        $Info[2] = hex($Info[2]);
    }
    return @Info;
}

sub readSymbols($)
{
    my $Lib_Path = $_[0];
    my $Lib_Name = getFilename($Lib_Path);
    
    my $Dynamic = ($Lib_Name=~/\.so(\.|\Z)/);
    my $Dbg = ($Lib_Name=~/\.debug\Z/);
    
    if(not checkCmd($EU_READELF)) {
        exitStatus("Not_Found", "can't find \"eu-readelf\" from Elfutils");
    }
    
    my %SectionInfo;
    my %KSect;
    
    my $Cmd = $EU_READELF_L." -S \"$Lib_Path\" 2>\"$TMP_DIR/error\"";
    foreach (split(/\n/, `$Cmd`))
    {
        if(/\[\s*(\d+)\]\s+([\w\.]+)/)
        {
            my ($Num, $Name) = ($1, $2);
            
            $SectionInfo{$Num} = $Name;
            
            if(defined $KernelExport)
            {
                if($Name=~/\A(__ksymtab|__ksymtab_gpl)\Z/) {
                    $KSect{$1} = 1;
                }
            }
        }
    }
    
    if(defined $KernelExport)
    {
        if(not keys(%KSect))
        {
            printMsg("ERROR", "can't find __ksymtab or __ksymtab_gpl sections in the object");
            exit(1);
        }
        
        foreach my $Name (sort keys(%KSect))
        {
            $Cmd = $OBJDUMP." --section=$Name -d \"$Lib_Path\" 2>\"$TMP_DIR/error\"";
            
            foreach my $Line (split(/\n/, qx/$Cmd/))
            {
                if($Line=~/<__ksymtab_(.+?)>/)
                {
                    $KSymTab{$1} = 1;
                }
            }
        }
    }
    
    if($Dynamic)
    { # dynamic library specifics
        $Cmd = $EU_READELF_L." -d \"$Lib_Path\" 2>\"$TMP_DIR/error\"";
        foreach (split(/\n/, `$Cmd`))
        {
            if(/NEEDED.+\[([^\[\]]+)\]/)
            { # dependencies:
              # 0x00000001 (NEEDED) Shared library: [libc.so.6]
                $Library_Needed{$1} = 1;
            }
        }
    }
    
    my $ExtraPath = undef;
    
    if($ExtraInfo)
    {
        mkpath($ExtraInfo);
        $ExtraPath = $ExtraInfo."/elf-info";
    }
    
    $Cmd = $EU_READELF_L." -s \"$Lib_Path\" 2>\"$TMP_DIR/error\"";
    
    if($ExtraPath)
    { # debug mode
        # write to file
        system($Cmd." >\"$ExtraPath\"");
        open(LIB, $ExtraPath);
    }
    else
    { # write to pipe
        open(LIB, $Cmd." |");
    }
    
    my (%Symbol_Value, %Value_Symbol) = ();
    
    my $symtab = undef; # indicates that we are processing 'symtab' section of 'readelf' output
    while(<LIB>)
    {
        if($Dynamic and not $Dbg)
        { # dynamic library specifics
            if(defined $symtab)
            {
                if(index($_, "'.dynsym'")!=-1)
                { # dynamic table
                    $symtab = undef;
                }
                if(not $AllSymbols)
                { # do nothing with symtab
                    # next;
                }
            }
            elsif(index($_, "'.symtab'")!=-1)
            { # symbol table
                $symtab = 1;
            }
        }
        if(my ($Value, $Size, $Type, $Bind, $Vis, $Ndx, $Symbol) = readline_ELF($_))
        { # read ELF entry
            $Symbol_Bind{$Symbol} = $Bind;
            if(index($Symbol, '@')!=-1)
            {
                if($Symbol=~/\A(.+?)\@/) {
                    $Symbol_Bind{$1} = $Bind;
                }
            }
            
            if(not $symtab)
            { # dynsym
                if(skipSymbol($Symbol)) {
                    next;
                }
                
                if($Ndx eq "UNDEF")
                { # ignore interfaces that are imported from somewhere else
                    $Library_UndefSymbol{$TargetName}{$Symbol} = 0;
                    next;
                }
                
                if(defined $KernelExport)
                {
                    if($Bind ne "LOCAL")
                    {
                        if(index($Symbol, "sys_")==0
                        or index($Symbol, "SyS_")==0) {
                            $KSymTab{$Symbol} = 1;
                        }
                    }
                    
                    if(not defined $KSymTab{$Symbol}) {
                        next;
                    }
                }
                
                if($Bind ne "LOCAL") {
                    $Library_Symbol{$TargetName}{$Symbol} = ($Type eq "OBJECT")?-$Size:1;
                }
                
                if(not defined $OBJ_LANG)
                {
                    if(index($Symbol, "_Z")==0)
                    {
                        $OBJ_LANG = "C++";
                    }
                }
            }
            
            if($Ndx ne "UNDEF" and $Value!~/\A0+\Z/)
            {
                $Symbol_Value{$Symbol} = $Value;
                $Value_Symbol{$Value}{$Symbol} = 1;

                if(defined $ExtraDump)
                {
                    $SymbolAttribute{$Symbol} = {
                        "Val" => $Value,
                        "Size" => $Size,
                        "Kind" => $Type,
                        "Bind" => $Bind,
                        "Vis" => $Vis,
                        "Ndx" => $Ndx
                    };
                }
            }
            
            if(not $symtab)
            {
                foreach ($SectionInfo{$Ndx}, "")
                {
                    my $Val = $Value;
                    
                    $SymbolTable{$_}{$Val}{$Symbol} = 1;
                    
                    if($Val=~s/\A[0]+//)
                    {
                        if($Val eq "") {
                            $Val = "0";
                        }
                        $SymbolTable{$_}{$Val}{$Symbol} = 1;
                    }
                }
            }
        }
    }
    close(LIB);
    
    if(not defined $Library_Symbol{$TargetName}) {
        return;
    }
    
    my %Found = ();
    foreach my $Symbol (sort keys(%Symbol_Value))
    {
        next if(index($Symbol, '@')==-1);
        if(my $Value = $Symbol_Value{$Symbol})
        {
            foreach my $Symbol_SameValue (sort keys(%{$Value_Symbol{$Value}}))
            {
                if($Symbol_SameValue ne $Symbol
                and index($Symbol_SameValue, '@')==-1)
                {
                    $SymVer{$Symbol_SameValue} = $Symbol;
                    $Found{$Symbol} = 1;
                    
                    if(index($Symbol, '@@')==-1) {
                        last;
                    }
                }
            }
        }
    }
    
    # default
    foreach my $Symbol (sort keys(%Symbol_Value))
    {
        next if(defined $Found{$Symbol});
        next if(index($Symbol, '@@')==-1);
        
        if($Symbol=~/\A([^\@]*)\@\@/
        and not $SymVer{$1})
        {
            $SymVer{$1} = $Symbol;
            $Found{$Symbol} = 1;
        }
    }
    
    # non-default
    foreach my $Symbol (sort keys(%Symbol_Value))
    {
        next if(defined $Found{$Symbol});
        next if(index($Symbol, '@')==-1);
        
        if($Symbol=~/\A([^\@]*)\@([^\@]*)/
        and not $SymVer{$1})
        {
            $SymVer{$1} = $Symbol;
            $Found{$Symbol} = 1;
        }
    }
    
    if(not defined $OBJ_LANG)
    {
        $OBJ_LANG = "C";
    }
}

sub readAltInfo($)
{
    my $Path = $_[0];
    my $Name = getFilename($Path);
    
    if(not checkCmd($EU_READELF)) {
        exitStatus("Not_Found", "can't find \"$EU_READELF\" command");
    }
    
    printMsg("INFO", "Reading alternate debug-info");
    
    my $ExtraPath = undef;
    
    # lines info
    if($ExtraInfo)
    {
        $ExtraPath = $ExtraInfo."/alt";
        mkpath($ExtraPath);
        $ExtraPath .= "/debug_line";
    }
    
    if($ExtraPath)
    {
        system($EU_READELF_L." -N --debug-dump=line \"$Path\" 2>\"$TMP_DIR/error\" >\"$ExtraPath\"");
        open(SRC, $ExtraPath);
    }
    else {
        open(SRC, $EU_READELF_L." -N --debug-dump=line \"$Path\" 2>\"$TMP_DIR/error\" |");
    }
    
    my $DirTable_Def = undef;
    my %DirTable = ();
    
    while(<SRC>)
    {
        if(defined $AddDirs)
        {
            if(/Directory table/i)
            {
                $DirTable_Def = 1;
                next;
            }
            elsif(/File name table/i)
            {
                $DirTable_Def = undef;
                next;
            }
            
            if(defined $DirTable_Def)
            {
                if(/\A\s*(.+?)\Z/) {
                    $DirTable{keys(%DirTable)+1} = $1;
                }
                elsif(/\A\s*(\d+)\s+(.+?)\s+\(\d+\)\Z/)
                { # F34
                    $DirTable{$1} = $2;
                }
            }
        }
        
        my ($Num, $Dir, $File) = ();
        
        if(/(\d+)\s+(\d+)\s+\d+\s+\d+\s+([^ ]+)/) {
            ($Num, $Dir, $File) = ($1, $2, $3)
        }
        elsif(/(\d+)\s+([^ ]+)\s+\(\d+\)\,\s+(\d+)/)
        {  # F34
            ($Num, $File, $Dir) = ($1, $2, $3);
        }
        
        if($File)
        {
            chomp($File);
            
            if(defined $AddDirs)
            {
                if(my $DName = $DirTable{$Dir})
                {
                    $File = $DName."/".$File;
                }
            }
            
            $SourceFile_Alt{0}{$Num} = $File;
        }
    }
    close(SRC);
    
    # debug info
    if($ExtraInfo)
    {
        $ExtraPath = $ExtraInfo."/alt";
        mkpath($ExtraPath);
        $ExtraPath .= "/debug_info";
    }
    
    my $INFO_fh;
    
    if($ExtraPath)
    {
        system($EU_READELF_L." -N --debug-dump=info \"$Path\" 2>\"$TMP_DIR/error\" >\"$ExtraPath\"");
        open($INFO_fh, $ExtraPath);
    }
    else {
        open($INFO_fh, $EU_READELF_L." -N --debug-dump=info \"$Path\" 2>\"$TMP_DIR/error\" |");
    }
    
    readDWARFDump($INFO_fh, 0);
}

sub readDWARFInfo($)
{
    my $Path = $_[0];
    
    my $Dir = getDirname($Path);
    my $Name = getFilename($Path);
    
    if(not checkCmd($EU_READELF)) {
        exitStatus("Not_Found", "can't find \"$EU_READELF\" command");
    }
    
    if(-s $Path > 1024*1024*100) {
        $TooBig = 1;
    }
    
    my $AddOpt = "";
    if(not defined $AddrToName)
    { # disable search of symbol names
        $AddOpt .= " -N";
    }
    
    my $Sect = `$EU_READELF_L -S \"$Path\" 2>\"$TMP_DIR/error\"`;
    
    if($Sect!~/\.z?debug_info/)
    { # No DWARF info
        if(my $DebugFile = getDebugFile($Path, "gnu_debuglink"))
        {
            my $DPath = $DebugFile;
            my $DName = getFilename($DPath);
            
            printMsg("INFO", "Found link to $DName (gnu_debuglink)");
            
            if(my $DDir = getDirname($Path))
            {
                $DPath = $DDir."/".$DPath;
            }
            
            my $Found = undef;
            
            if(defined $SearchDirDebuginfo)
            {
                if(-f $SearchDirDebuginfo."/".$DName) {
                    $Found = $SearchDirDebuginfo."/".$DName;
                }
                else
                {
                    my @Files = findFiles($SearchDirDebuginfo, "f");
                    
                    foreach my $F (@Files)
                    {
                        if(getFilename($F) eq $DName)
                        {
                            $Found = $F;
                            last;
                        }
                    }
                }
            }
            elsif(-f $DPath
            and $DPath ne $Path) {
                $Found = $DPath;
            }
            
            if($Found and $Found ne $Path)
            {
                printMsg("INFO", "Reading debug-info file $DName linked from gnu_debuglink");
                return readDWARFInfo($Found);
            }
            else
            {
                printMsg("ERROR", "missed debug-info file $DName linked from gnu_debuglink (try --search-debuginfo=DIR option)");
                return 0;
            }
        }
        return 0;
    }
    elsif(not defined $AltDebugInfoOpt)
    {
        if($Sect=~/\.gnu_debugaltlink/)
        {
            if(my $AltObj = getDebugAltLink($Path))
            {
                $AltDebugInfo = $AltObj;
                readAltInfo($AltObj);
            }
            else {
                exitStatus("Error", "can't read gnu_debugaltlink");
            }
        }
    }
    
    if($AltDebugInfo)
    {
        if($TooBig) {
            printMsg("WARNING", "input object is compressed and large, may require a lot of RAM memory to process");
        }
    }
    
    printMsg("INFO", "Reading debug-info");
    
    my $ExtraPath = undef;
    
    # ELF header
    if($ExtraInfo)
    {
        mkpath($ExtraInfo);
        $ExtraPath = $ExtraInfo."/elf-header";
    }
    
    if($ExtraPath)
    {
        system($EU_READELF_L." -h \"$Path\" 2>\"$TMP_DIR/error\" >\"$ExtraPath\"");
        open(HEADER, $ExtraPath);
    }
    else {
        open(HEADER, $EU_READELF_L." -h \"$Path\" 2>\"$TMP_DIR/error\" |");
    }
    
    my %Header = ();
    while(<HEADER>)
    {
        if(/\A\s*([\w ]+?)\:\s*(.+?)\Z/) {
            $Header{$1} = $2;
        }
    }
    close(HEADER);
    
    $SYS_ARCH = $Header{"Machine"};
    
    if($SYS_ARCH=~/80\d86/
    or $SYS_ARCH=~/i\d86/)
    { # i386, i586, etc.
        $SYS_ARCH = "x86";
    }
    
    if($SYS_ARCH=~/amd64/i
    or $SYS_ARCH=~/x86\-64/i)
    { # amd64
        $SYS_ARCH = "x86_64";
    }
    
    initRegs();
    
    # ELF sections
    if($ExtraInfo)
    {
        mkpath($ExtraInfo);
        $ExtraPath = $ExtraInfo."/elf-sections";
    }
    
    if($ExtraPath)
    {
        system($EU_READELF_L." -S \"$Path\" 2>\"$TMP_DIR/error\" >\"$ExtraPath\"");
        open(HEADER, $ExtraPath);
    }
    
    # source info
    if($ExtraInfo)
    {
        mkpath($ExtraInfo);
        $ExtraPath = $ExtraInfo."/debug_line";
    }
    
    if($ExtraPath)
    {
        system($EU_READELF_L." $AddOpt --debug-dump=line \"$Path\" 2>\"$TMP_DIR/error\" >\"$ExtraPath\"");
        open(SRC, $ExtraPath);
    }
    else {
        open(SRC, $EU_READELF_L." $AddOpt --debug-dump=line \"$Path\" 2>\"$TMP_DIR/error\" |");
    }
    
    my $Offset = undef;
    my $DirTable_Def = undef;
    my %DirTable = ();
    
    while(<SRC>)
    {
        if(defined $AddDirs)
        {
            if(/Directory table/i)
            {
                $DirTable_Def = 1;
                %DirTable = ();
                next;
            }
            elsif(/File name table/i)
            {
                $DirTable_Def = undef;
                next;
            }
            
            if(defined $DirTable_Def)
            {
                if(/\A\s*([^\[\]\(\)]+?)\Z/) {
                    $DirTable{keys(%DirTable)+1} = $1;
                }
                elsif(/\A\s*(\d+)\s+(.+?)\s+\(\d+\)\Z/)
                { # F34
                    $DirTable{$1} = $2;
                }
            }
        }
        
        if(index($_, "Table")!=-1
        and /Table at offset (\w+)/) {
            $Offset = $1;
        }
        elsif(defined $Offset)
        {
            my ($Num, $Dir, $File) = ();
            
            if(/(\d+)\s+(\d+)\s+\d+\s+\d+\s+([^ ]+)/) {
                ($Num, $Dir, $File) = ($1, $2, $3);
            }
            elsif(/(\d+)\s+([^ ]+)\s+\(\d+\)\,\s+(\d+)/)
            { # F34
                ($Num, $File, $Dir) = ($1, $2, $3);
            }
            
            if($File)
            {
                chomp($File);
                
                if(defined $AddDirs)
                {
                    if(my $DName = $DirTable{$Dir})
                    {
                        $File = $DName."/".$File;
                    }
                }
                
                $SourceFile{$Offset}{$Num} = $File;
            }
        }
    }
    close(SRC);
    
    # debug_loc
    if($ExtraInfo)
    {
        mkpath($ExtraInfo);
        $ExtraPath = $ExtraInfo."/debug_loc";
    }
    
    if($ExtraPath)
    {
        system($EU_READELF_L." $AddOpt --debug-dump=loc \"$Path\" 2>\"$TMP_DIR/error\" >\"$ExtraPath\"");
        open(LOC, $ExtraPath);
    }
    else {
        open(LOC, $EU_READELF_L." $AddOpt --debug-dump=loc \"$Path\" 2>\"$TMP_DIR/error\" |");
    }
    
    my $Offset = undef;
    
    while(<LOC>)
    {
        if(/\A \[\s*(\w+)\].*\[\s*\w+\]\s*(.+)\Z/) {
            $DebugLoc{$1} = $2;
        }
        elsif(/\A \[\s*(\w+)\]/) {
            $DebugLoc{$1} = "";
        }
        elsif(/Offset:\s+(.+?),/)
        { # F34
            $Offset = $1;
        }
        elsif($Offset and /\A\s+\[\s*\w+\]\s*(.+)\Z/)
        { # F34
            $DebugLoc{$Offset} = $1;
        }
    }
    close(LOC);
    
    # dwarf
    if($ExtraInfo)
    {
        mkpath($ExtraInfo);
        $ExtraPath = $ExtraInfo."/debug_info";
    }
    
    my $INFO_fh;
    
    if($Dir)
    { # to find ".dwz" directory (Fedora)
        chdir($Dir);
    }
    if($ExtraPath)
    {
        system($EU_READELF_L." $AddOpt --debug-dump=info \"$Name\" 2>\"$TMP_DIR/error\" >\"$ExtraPath\"");
        open($INFO_fh, $ExtraPath);
    }
    else {
        open($INFO_fh, $EU_READELF_L." $AddOpt --debug-dump=info \"$Name\" 2>\"$TMP_DIR/error\" |");
    }
    chdir($ORIG_DIR);
    
    readDWARFDump($INFO_fh, 1);
    
    if(my $Err = readFile("$TMP_DIR/error"))
    { # eu-readelf: cannot get next DIE: invalid DWARF
        if($Err=~/invalid DWARF/i)
        {
            if($Loud) {
                printMsg("ERROR", $Err);
            }
            exitStatus("Invalid_DWARF", "invalid DWARF info");
        }
    }
    
    return 1;
}

sub getSource($)
{
    my $ID = $_[0];
    
    if(defined $DWARF_Info{$ID}{"file"})
    {
        my $File = $DWARF_Info{$ID}{"file"};
        my $Unit = $DWARF_Info{$ID}{"unit"};
        
        my $Name = undef;
        
        if($ID>=0) {
            $Name = $SourceFile{$Unit}{$File};
        }
        else
        { # imported
            $Name = $SourceFile_Alt{0}{$File};
        }
        
        return $Name;
    }
    
    return undef;
}

sub readDWARFDump($$)
{
    my ($FH, $Primary) = @_;
    
    my $TypeUnit_Sign = undef;
    my $TypeUnit_Offset = undef;
    my $Type_Offset = undef;
    
    my $Shift_Enabled = 1;
    my $ID_Shift = undef;
    
    my $CUnit = undef;
    
    if($AltDebugInfo) {
        $Compressed = 1;
    }
    
    my $ID = undef;
    my $Kind = undef;
    my $NS = undef;
    
    my $MAX_ID = undef;
    
    my %Shift = map {$_=>1} (
        "specification",
        "spec",
        "type",
        "sibling",
        "object_pointer",
        "objptr",
        "containing_type",
        "container",
        "abstract_origin",
        "orig",
        "import",
        "signature"
    );
    
    my %SkipNode = (
        "imported_declaration" => 1,
        "imported_module" => 1
    );
    
    my %SkipAttr = (
        "high_pc" => 1,
        "frame_base" => 1,
        "encoding" => 1,
        "Compilation" => 1,
        "comp_dir" => 1,
        "declaration" => 1,
        "prototyped" => 1,
        "GNU_vector" => 1,
        "GNU_all_call_sites" => 1,
        "explicit" => 1
    );
    
    my %RenameAttr = (
        "data_member_location" => "mloc",
        "decl_file" => "file",
        "decl_line" => "line",
        "linkage_name" => "linkage",
        "object_pointer" => "objptr",
        "artificial" => "art",
        "external" => "ext",
        "specification" => "spec",
        "byte_size" => "size",
        "accessibility" => "access",
        "const_value" => "cval",
        "containing_type" => "container",
        "abstract_origin" => "orig",
        "virtuality" => "virt",
        "vtable_elem_location" => "vloc"
    );
    
    my %RenameKind = (
        "formal_parameter" => "param",
        "subprogram" => "prog",
        "unspecified_parameters" => "unspec_params",
        "template_type_parameter" => "tmpl_param"
    );
    
    my %MarkByUnit = (
        "member" => 1,
        "subprogram" => 1,
        "prog" => 1,
        "variable" => 1
    );
    
    my $Lexical_Block = undef;
    my $Inlined_Block = undef;
    my $Subprogram_Block = undef;
    my $Skip_Block = undef;
    
    while(my $Line = <$FH>)
    {
        if(defined $ID and $Line=~/\A\s*(\w+)\s+(.+?)\s*\Z/)
        {
            if(defined $Skip_Block) {
                next;
            }
            
            my $Attr = $1;
            my $Val = $2;
            
            if(defined $RenameAttr{$Attr}) {
                $Attr = $RenameAttr{$Attr};
            }
            
            if(index($Val, "(flag")==0)
            { # artificial, external (on Fedora)
              # flag_present
                $Val = 1;
            }
            
            if(defined $Compressed)
            {
                if($Kind eq "imported_unit") {
                    next;
                }
            }
            
            if($Kind eq "member")
            {
                if($Attr eq "mloc") {
                    delete($DWARF_Info{$ID}{"unit"});
                }
            }
            
            if($Attr eq "sibling")
            {
                if($Kind ne "structure_type") {
                    next;
                }
            }
            elsif($Attr eq "Type")
            {
                if($Line=~/Type\s+signature:\s*0x(\w+)/) {
                    $TypeUnit_Sign = $1;
                }
                if($Line=~/Type\s+offset:\s*0x(\w+)/) {
                    $Type_Offset = hex($1);
                }
                if($Line=~/Type\s+unit\s+at\s+offset\s+(\d+)/) {
                    $TypeUnit_Offset = $1;
                }
                next;
            }
            elsif(defined $SkipAttr{$Attr})
            { # unused
                next;
            }
            
            if($Val=~/\A\s*\(([^()]*)\)\s*\[\s*(\w+)\]\s*\Z/)
            { # ref4, ref_udata, ref_addr, etc.
                $Val = hex($2);
                
                if($1 eq "GNU_ref_alt") {
                    $Val = -$Val;
                }
            }
            elsif($Attr eq "name")
            {
                $Val=~s/\A\([^()]*\)\s*\"(.*)\"\Z/$1/;
                
                if(defined $LambdaSupport)
                {
                    if(index($Val, "<lambda(")==0)
                    {
                        $Val=~s/\A</{/;
                        $Val=~s/>\Z/}/;
                    }
                }
            }
            elsif(index($Attr, "linkage_name")!=-1 or $Attr eq "linkage")
            {
                $Val=~s/\A\([^()]*\)\s*\"(.*)\"\Z/$1/;
                $Attr = "linkage";
            }
            elsif(index($Attr, "location")!=-1 or $Attr eq "mloc" or $Attr eq "vloc")
            {
                if($Val=~/\)\s*\Z/)
                { # value on the next line
                    my $NL = <$FH>;
                    $Val .= $NL;

                    if(defined $ExtraDump)
                    {
                        if($NL=~/\A\s{4,}\[\s*(\w+)\]\s*(piece \d+|\w+)/)
                        {
                            $FullLoc{$ID}{$1} = $2;
                        }
                    }
                    
                    if(index($Val, "GNU_entry_value")!=-1)
                    { # value on the next line
                        $NL = <$FH>;
                        $Val .= $NL;
                    }
                }
                
                if($Val=~/\A\(\w+\)\s*(-?)(\w+)\Z/)
                { # (data1) 1c
                    if ($2 != 0xFFFFFFFFFFFFFFFF) {
                        $Val = hex($2);
                        if($1) {
                            $Val = -$Val;
                       }
                    }
                }
                else
                {
                    if($Val=~/ (-?\d+)\Z/) {
                        $Val = $1;
                    }
                    else
                    {
                        if($Attr eq "location"
                        and $Kind eq "param")
                        {
                            if($Val=~/location list\s+\[\s*(\w+)\]\Z/)
                            {
                                $Attr = "location_list";
                                $Val = $1;
                            }
                            elsif($Val=~/ reg(\d+)\Z/)
                            {
                                $Attr = "register";
                                $Val = $1;
                            }
                        }
                    }
                }
            }
            elsif($Attr eq "access")
            {
                $Val=~s/\A\(.+?\)\s*//;
                $Val=~s/\s*\(.+?\)\Z//;
                
                # NOTE: members: private by default
            }
            else
            {
                $Val=~s/\A\(\w+\)\s*//;
                
                if(substr($Val, 0, 1) eq "{"
                and $Val=~/{(.+)}/)
                { # {ID}
                    $Val = $1;
                    $Post_Change{$ID} = 1;
                }
            }
            
            if($Val eq "")
            {
                if($Attr eq "ext") {
                    next;
                }
            }
            
            if(defined $Shift_Enabled and $ID_Shift)
            {
                if(defined $Shift{$Attr}
                and not $Post_Change{$ID}) {
                    $Val += $ID_Shift;
                }
                
                # $DWARF_Info{$ID}{"rID"} = $ID-$ID_Shift;
            }
            
            if(not $Primary)
            {
                if(defined $Shift{$Attr}) {
                    $Val = -$Val;
                }
            }
            
            if($Kind ne "partial_unit"
            and $Kind ne "imported_unit")
            {
                if($Attr ne "stmt_list") {
                    $DWARF_Info{$ID}{$Attr} = "$Val";
                }
            }
            
            if($Kind eq "compile_unit")
            {
                if($Attr eq "stmt_list")
                {
                    $CUnit = $Val;
                    $Partial = undef
                }
                
                if(not defined $LIB_LANG)
                {
                    if($Attr eq "language")
                    {
                        if(index($Val, "Assembler")==-1)
                        {
                            $Val=~s/\s*\(.+?\)\Z//;
                            
                            if($Val=~/C\d/i) {
                                $LIB_LANG = "C";
                            }
                            elsif($Val=~/C\+\+|C_plus_plus/i) {
                                $LIB_LANG = "C++";
                            }
                            else {
                                $LIB_LANG = $Val;
                            }
                        }
                    }
                }
                
                if(not defined $SYS_COMP and not defined $SYS_GCCV)
                {
                    if($Attr eq "producer")
                    {
                        if(index($Val, "GNU AS")==-1)
                        {
                            $Val=~s/\A\"//;
                            $Val=~s/\"\Z//;
                            
                            if($Val=~/GNU\s+(C\d*|C\+\+\d*|GIMPLE)\s+(.+)\Z/)
                            {
                                $SYS_GCCV = $2;
                                if($SYS_GCCV=~/\A(\d+\.\d+)(\.\d+|)/)
                                { # 4.6.1 20110627 (Mandriva)
                                    $SYS_GCCV = $1.$2;
                                }
                            }
                            elsif($Val=~/clang\s+version\s+([^\s\(]+)/) {
                                $SYS_CLANGV = $1;
                            }
                            else {
                                $SYS_COMP = $Val;
                            }
                            
                            if(not defined $KeepRegsAndOffsets)
                            {
                                my %Opts = ();
                                while($Val=~s/(\A| )(\-O([0-3]|g))( |\Z)/ /) {
                                    $Opts{keys(%Opts)} = $2;
                                }
                                
                                if(keys(%Opts))
                                {
                                    if($Opts{keys(%Opts)-1} ne "-Og")
                                    {
                                        if(not defined $Quiet) {
                                            printMsg("WARNING", "incompatible build option detected: ".$Opts{keys(%Opts)-1}." (required -Og for better analysis)");
                                        }
                                        $IncompatibleOpt = 1;
                                    }
                                }
                                else
                                {
                                    if(not defined $Quiet) {
                                        printMsg("WARNING", "the object should be compiled with -Og option for better analysis");
                                    }
                                    $IncompatibleOpt = 1;
                                }
                            }
                            
                            if(index($Val, "-fkeep-inline-functions")!=-1) {
                                $FKeepInLine = 1;
                            }
                        }
                    }
                }
            }
            elsif($Kind eq "type_unit")
            {
                if($Attr eq "stmt_list")
                {
                    $CUnit = $Val;
                    $Partial = 1;
                }
            }
            elsif($Kind eq "partial_unit")
            { # support for dwz
                if($Attr eq "stmt_list")
                {
                    $CUnit = $Val;
                    $Partial = 1;
                }
            }
        }
        elsif(defined $ExtraDump and $Line=~/\A\s{4,}\[\s*(\w+)\]\s*(piece \d+|\w+)/)
        {
            $FullLoc{$ID}{$1} = $2;
        }
        elsif($Line=~/\A \[\s*(\w+)\](\s*)(\w+)/)
        {
            $ID = hex($1);
            $NS = length($2);
            $Kind = $3;
            
            if(defined $RenameKind{$Kind}) {
                $Kind = $RenameKind{$Kind};
            }
            
            if(not defined $Compressed)
            {
                if($Kind eq "partial_unit" or $Kind eq "type_unit")
                { # compressed debug_info
                    $Compressed = 1;
                    
                    if($TooBig) {
                        printMsg("WARNING", "input object is compressed and large, may require a lot of RAM memory to process");
                    }
                }
            }
            
            if($Kind eq "compile_unit" and $CUnit
            and not defined $AllUnits)
            { # read the previous compile unit
                completeDump($Primary);
                
                if($Primary) {
                    readABI();
                }
            }
            
            $Skip_Block = undef;
            
            if(defined $SkipNode{$Kind})
            {
                $Skip_Block = 1;
                next;
            }
            
            if($Kind eq "lexical_block")
            {
                if(defined $Lexical_Block)
                {
                    if(length($NS)<=length($Lexical_Block)) {
                        $Lexical_Block = $NS;
                    }
                }
                else {
                    $Lexical_Block = $NS;
                }
                $Skip_Block = 1;
                next;
            }
            else
            {
                if(defined $Lexical_Block)
                {
                    if($NS>$Lexical_Block)
                    {
                        $LexicalId{$ID} = 1;
                        if(not $LambdaSupport)
                        {
                            $Skip_Block = 1;
                            next;
                        }
                    }
                    else
                    { # end of lexical block
                        $Lexical_Block = undef;
                    }
                }
            }
            
            if($Kind eq "inlined_subroutine")
            {
                $Inlined_Block = $NS;
                $Skip_Block = 1;
                next;
            }
            else
            {
                if(defined $Inlined_Block)
                {
                    if($NS>$Inlined_Block)
                    {
                        $Skip_Block = 1;
                        next;
                    }
                    else
                    { # end of inlined subroutine
                        $Inlined_Block = undef;
                    }
                }
            }
            
            if($Kind eq "prog")
            {
                $Subprogram_Block = $NS;
            }
            else
            {
                if(defined $Subprogram_Block)
                {
                    if($NS>$Subprogram_Block)
                    {
                        if($Kind eq "variable")
                        { # temp variables
                            $Skip_Block = 1;
                            next;
                        }
                    }
                    else
                    { # end of subprogram block
                        $Subprogram_Block = undef;
                    }
                }
            }
            
            if(not $Primary) {
                $ID = -$ID;
            }
            
            if(defined $Shift_Enabled)
            {
                if($Kind eq "type_unit")
                {
                    if(not defined $ID_Shift)
                    {
                        if($ID_Shift<=$MAX_ID) {
                            $ID_Shift = $MAX_ID;
                        }
                        else {
                            $ID_Shift = 0;
                        }
                    }
                }
                
                if($ID_Shift) {
                    $ID += $ID_Shift;
                }
            }
            
            if(defined $TypeUnit_Sign)
            {
                if($Kind ne "type_unit"
                and $Kind ne "namespace")
                {
                    if($TypeUnit_Offset+$Type_Offset+$ID_Shift==$ID)
                    {
                        $TypeUnit{$TypeUnit_Sign} = "$ID";
                        $TypeUnit_Sign = undef;
                    }
                }
            }
            
            if($Kind ne "partial_unit"
            and $Kind ne "imported_unit")
            {
                $DWARF_Info{$ID} = {};
                $DWARF_Info{$ID}{"kind"} = $Kind;
                $DWARF_Info{$ID}{"ns"} = $NS;
                
                if(defined $CUnit)
                {
                    if(defined $MarkByUnit{$Kind}
                    or defined $TypeType{$Kind}) {
                        $DWARF_Info{$ID}{"unit"} = $CUnit;
                    }
                }
                
                if($ID>0) {
                    push(@IDs, $ID);
                }
                else {
                    push(@IDs_I, $ID);
                }
            }
            
            if(not defined $ID_Shift) {
                $MAX_ID = $ID;
            }
        }
        elsif(not defined $SYS_WORD
        and $Line=~/Address\s*size:\s*(\d+)/i)
        {
            $SYS_WORD = $1;
        }
    }
    
    close($FH);
    
    if($Primary and not defined $ID) {
        printMsg("ERROR", "the debuginfo looks empty or corrupted");
    }
    
    # read the last compile unit
    completeDump($Primary);
    
    if($Primary) {
        readABI();
    }
}

sub readVtables($)
{
    my $Path = $_[0];
    
    $Path = abs_path($Path);
    
    my $Dir = getDirname($Path);
    
    if(index($LIB_LANG, "C++")!=-1
    or $OBJ_LANG eq "C++")
    {
        printMsg("INFO", "Reading v-tables");
        
        if(checkCmd($VTABLE_DUMPER))
        {
            if(my $Version = `$VTABLE_DUMPER -dumpversion`)
            {
                if(cmpVersions($Version, $VTABLE_DUMPER_VERSION)<0)
                {
                    printMsg("ERROR", "the version of Vtable-Dumper should be $VTABLE_DUMPER_VERSION or newer");
                    return;
                }
            }
        }
        else
        {
            printMsg("ERROR", "cannot find \'$VTABLE_DUMPER\'");
            return;
        }
        
        my $ExtraPath = $TMP_DIR."/v-tables";
        
        if($ExtraInfo)
        {
            mkpath($ExtraInfo);
            $ExtraPath = $ExtraInfo."/v-tables";
        }
        
        my $LdPaths = $Dir;
        
        if(defined $LdLibraryPath) {
            $LdPaths .= ":".$LdLibraryPath;
        }
        
        system("LD_LIBRARY_PATH=\"$LdPaths\" $VTABLE_DUMPER -mangled -demangled \"$Path\" >\"$ExtraPath\"");
        
        my $Content = readFile($ExtraPath);
        foreach my $ClassInfo (split(/\n\n\n/, $Content))
        {
            if($ClassInfo=~/\AVtable\s+for\s+(.+)\n((.|\n)+)\Z/i)
            {
                my ($CName, $VTable) = ($1, $2);
                my @Entries = split(/\n/, $VTable);
                
                foreach (1 .. $#Entries)
                {
                    my $Entry = $Entries[$_];
                    if($Entry=~/\A(\d+)\s+(.+)\Z/) {
                        $VirtualTable{$CName}{$1} = $2;
                    }
                }

                if(defined $ExtraDump)
                {
                    if($Entries[0]=~/\A(\w+)\:/)
                    {
                        $VTable_Symbol{$CName} = $1;
                        $VTable_Class{$1} = $CName;
                    }
                }
            }
        }
    }
    
    if(keys(%VirtualTable))
    {
        foreach my $Tid (sort keys(%TypeInfo))
        {
            if($TypeInfo{$Tid}{"Type"}=~/\A(Struct|Class)\Z/)
            {
                my $TName = $TypeInfo{$Tid}{"Name"};
                $TName=~s/\bstruct //g;
                if(defined $VirtualTable{$TName})
                {
                    $TypeInfo{$Tid}{"VTable"} = $VirtualTable{$TName};

                    if(defined $ExtraDump)
                    {
                        $TypeInfo{$Tid}{"VTable_Sym"} = $VTable_Symbol{$TName};
                    }
                    $TypeInfo{$Tid}{"VTable"} = $VirtualTable{$TName};
                }
            }
        }
    }
}

sub createArchive($$)
{
    my ($Path, $To) = @_;
    if(not $To) {
        $To = ".";
    }
    
    if(not checkCmd("tar")) {
        exitStatus("Not_Found", "can't find \"tar\"");
    }
    if(not checkCmd("gzip")) {
        exitStatus("Not_Found", "can't find \"gzip\"");
    }
    
    my ($From, $Name) = sepPath($Path);
    my $Pkg = abs_path($To)."/".$Name.".".$COMPRESS;
    if(-e $Pkg) {
        unlink($Pkg);
    }
    system("tar", "-C", $From, "-czf", $Pkg, $Name);
    if($?)
    { # cannot allocate memory (or other problems with "tar")
        exitStatus("Error", "can't pack the ABI dump: ".$!);
    }
    unlink($Path);
    return $To."/".$Name.".".$COMPRESS;
}

sub createABIFile()
{
    printMsg("INFO", "Creating ABI dump");
    
    my %ABI = (
        "TypeInfo" => \%TypeInfo,
        "SymbolInfo" => \%SymbolInfo,
        "Symbols" => \%Library_Symbol,
        "UndefinedSymbols" => \%Library_UndefSymbol,
        "Needed" => \%Library_Needed,
        "SymbolVersion" => \%SymVer,
        "LibraryVersion" => $TargetVersion,
        "LibraryName" => $TargetName,
        "Language" => $LIB_LANG,
        "Headers" => \%HeadersInfo,
        "Sources" => \%SourcesInfo,
        "NameSpaces" => \%NestedNameSpaces,
        "Target" => "unix",
        "Arch" => $SYS_ARCH,
        "WordSize" => $SYS_WORD,
        "ABI_DUMP_VERSION" => $ABI_DUMP_VERSION,
        "ABI_DUMPER_VERSION" => $TOOL_VERSION,
    );
    
    if($SYS_GCCV) {
        $ABI{"GccVersion"} = $SYS_GCCV;
    }
    elsif($SYS_CLANGV) {
        $ABI{"ClangVersion"} = $SYS_CLANGV;
    }
    else {
        $ABI{"Compiler"} = $SYS_COMP;
    }

    if(defined $ExtraDump) {
        $ABI{"ExtraDump"} = "On";
    }

    if(defined $PublicHeadersPath) {
        $ABI{"PublicABI"} = "1";
    }
    
    if(defined $IncompatibleOpt)
    {
        $ABI{"MissedOffsets"} = "1";
        $ABI{"MissedRegs"} = "1";
    }
    
    if($StdOut)
    { # --stdout option
        print STDOUT Dumper(\%ABI);
    }
    else
    {
        my $DumpPath = "ABI.dump";
        if($OutputDump)
        { # user defined path
            $DumpPath = $OutputDump;
        }
        my $Archive = ($DumpPath=~s/\Q.$COMPRESS\E\Z//g);
        my ($DDir, $DName) = sepPath($DumpPath);
        
        my $DPath = $TMP_DIR."/".$DName;
        if(not $Archive) {
            $DPath = $DumpPath;
        }
        
        mkpath($DDir);
        
        open(DUMP, ">", $DPath) || die ("can't open file \'$DumpPath\': $!\n");
        print DUMP Dumper(\%ABI);
        close(DUMP);
        
        if(not -s $DPath) {
            exitStatus("Error", "can't create ABI dump because something is going wrong with the Data::Dumper module");
        }
        if($Archive) {
            $DumpPath = createArchive($DPath, $DDir);
        }
        
        printMsg("INFO", "\nThe object ABI has been dumped to:\n  $DumpPath");
    }
}

sub unmangleString($)
{
    my $Str = $_[0];
    
    $Str=~s/\AN(.+)E\Z/$1/;
    while($Str=~s/\A(\d+)//)
    {
        if(length($Str)==$1) {
            last;
        }
        
        $Str = substr($Str, $1, length($Str) - $1);
    }
    
    return $Str;
}

sub initABI()
{
    # register "void" type
    %{$TypeInfo{"1"}} = (
        "Name"=>"void",
        "Type"=>"Intrinsic"
    );
    $TName_Tid{"Intrinsic"}{"void"} = "1";
    $TName_Tids{"Intrinsic"}{"void"}{"1"} = 1;
    $Cache{"getTypeInfo"}{"1"} = 1;
    
    # register "..." type
    %{$TypeInfo{"-1"}} = (
        "Name"=>"...",
        "Type"=>"Intrinsic"
    );
    $TName_Tid{"Intrinsic"}{"..."} = "-1";
    $TName_Tids{"Intrinsic"}{"..."}{"-1"} = 1;
    $Cache{"getTypeInfo"}{"-1"} = 1;
}

sub completeDump($)
{
    my $Primary = $_[0];
    
    foreach my $ID (keys(%Post_Change))
    {
        if(my $Type = $DWARF_Info{$ID}{"type"})
        {
            if(my $To = $TypeUnit{$Type}) {
                $DWARF_Info{$ID}{"type"} = $To;
            }
        }
        if(my $Signature = $DWARF_Info{$ID}{"signature"})
        {
            if(my $To = $TypeUnit{$Signature}) {
                $DWARF_Info{$ID}{"signature"} = $To;
            }
        }
    }
    
    %Post_Change = ();
    %TypeUnit = ();
}

my %IsType = map {$_=>1} (
    "struct_type",
    "structure_type",
    "class_type",
    "union_type",
    "enumeration_type",
    "subroutine_type",
    "array_type"
);

my %MainKind = map {$_=>1} (
    "typedef",
    "subprogram",
    "prog",
    "variable",
    "namespace"
);

sub readABI()
{
    my %CurID = ();
    
    if(@IDs_I) {
        @IDs = (@IDs_I, @IDs);
    }
    
    my $TPack = undef;
    my $PPack = undef;
    my $NS_Pre = undef;
    
    foreach my $ID (@IDs)
    {
        $ID = "$ID";
        
        my $Kind = $DWARF_Info{$ID}{"kind"};
        my $NS = $DWARF_Info{$ID}{"ns"};
        my $Scope = $CurID{$NS-2};
        
        if(defined $NS_Pre and $NS<=$NS_Pre)
        {
            foreach (0 .. $NS_Pre-$NS) {
                delete($CurID{$NS+$_});
            }
        }
        
        $NS_Pre = $NS;
        
        if($Kind eq "typedef")
        {
            if($DWARF_Info{$Scope}{"kind"} eq "prog")
            {
                $NS = $DWARF_Info{$Scope}{"ns"};
                $Scope = $CurID{$NS-2};
            }
        }
        
        if($Kind ne "prog") {
            delete($DWARF_Info{$ID}{"ns"});
        }
        
        if(defined $IsType{$Kind}
        or defined $MainKind{$Kind})
        {
            if($Kind ne "variable"
            and $Kind ne "typedef")
            {
                $CurID{$NS} = $ID;
            }
            
            if($Scope)
            {
                $NameSpace{$ID} = $Scope;
                if($Kind eq "prog"
                or $Kind eq "variable")
                {
                    if($DWARF_Info{$Scope}{"kind"}=~/class|struct/)
                    {
                        $ClassMethods{$Scope} = 1;
                        if(my $Sp = $DWARF_Info{$Scope}{"spec"}) {
                            $ClassMethods{$Sp} = 1;
                        }
                    }
                }
            }
            
            if(my $Spec = $DWARF_Info{$ID}{"spec"}) {
                $SpecElem{$Spec} = $ID;
            }
            
            if(my $Orig = $DWARF_Info{$ID}{"orig"}) {
                $OrigElem{$Orig} = $ID;
            }
            
            if(defined $IsType{$Kind})
            {
                if(not $DWARF_Info{$ID}{"name"}
                and $DWARF_Info{$ID}{"linkage"})
                {
                    $DWARF_Info{$ID}{"name"} = unmangleString($DWARF_Info{$ID}{"linkage"});
                    
                    # free memory
                    delete($DWARF_Info{$ID}{"linkage"});
                }
            }
        }
        elsif($Kind eq "member")
        {
            if($Scope)
            {
                $NameSpace{$ID} = $Scope;
                
                if(not defined $DWARF_Info{$ID}{"mloc"}
                and $DWARF_Info{$Scope}{"kind"}=~/class|struct/)
                { # variable (global data)
                    next;
                }
            }
            
            $TypeMember{$Scope}{keys(%{$TypeMember{$Scope}})} = $ID;
        }
        elsif($Kind eq "enumerator")
        {
            $TypeMember{$Scope}{keys(%{$TypeMember{$Scope}})} = $ID;
        }
        elsif($Kind eq "inheritance")
        {
            my %In = ();
            $In{"id"} = $DWARF_Info{$ID}{"type"};
            
            if(my $Access = $DWARF_Info{$ID}{"access"})
            {
                if($Access ne "public")
                { # default inheritance access in ABI dump is "public"
                    $In{"access"} = $Access;
                }
            }
            
            if(defined $DWARF_Info{$ID}{"virt"}) {
                $In{"virtual"} = 1;
            }
            $Inheritance{$Scope}{keys(%{$Inheritance{$Scope}})} = \%In;
            
            # free memory
            delete($DWARF_Info{$ID});
        }
        elsif($Kind eq "param")
        {
            if(defined $PPack) {
                $FuncParam{$PPack}{keys(%{$FuncParam{$PPack}})} = $ID;
            }
            else {
                $FuncParam{$Scope}{keys(%{$FuncParam{$Scope}})} = $ID;
            }
        }
        elsif($Kind eq "unspec_params")
        {
            $FuncParam{$Scope}{keys(%{$FuncParam{$Scope}})} = $ID;
            $DWARF_Info{$ID}{"type"} = "-1"; # "..."
        }
        elsif($Kind eq "subrange_type")
        {
            if((my $Bound = $DWARF_Info{$ID}{"upper_bound"}) ne "") {
                $ArrayCount{$Scope} = $Bound + 1;
            }
            
            # free memory
            delete($DWARF_Info{$ID});
        }
        elsif($Kind eq "tmpl_param"
        or $Kind eq "template_value_parameter")
        {
            my %Info = ("key"=>$DWARF_Info{$ID}{"name"});
            
            if(defined $DWARF_Info{$ID}{"type"}) {
                $Info{"type"} = $DWARF_Info{$ID}{"type"};
            }
            else { # void
                $Info{"type"} = "1";
            }
            
            if(defined $DWARF_Info{$ID}{"cval"}) {
                $Info{"value"} = $DWARF_Info{$ID}{"cval"};
            }
            
            if(defined $DWARF_Info{$ID}{"default_value"}) {
                $Info{"default"} = 1;
            }
            
            if(defined $TPack) {
                $TmplParam{$TPack}{keys(%{$TmplParam{$TPack}})} = \%Info;
            }
            else {
                $TmplParam{$Scope}{keys(%{$TmplParam{$Scope}})} = \%Info;
            }
        }
        elsif($Kind eq "GNU_template_parameter_pack") {
            $TPack = $Scope;
        }
        elsif($Kind eq "GNU_formal_parameter_pack") {
            $PPack = $Scope;
        }
        
        if($Kind ne "GNU_template_parameter_pack")
        {
            if(index($Kind, "template_")==-1) {
                $TPack = undef;
            }
        }
        
        if($Kind ne "GNU_formal_parameter_pack")
        {
            if($Kind ne "param") {
                $PPack = undef;
            }
        }
    }
    
    # free memory
    %CurID = ();
    
    foreach my $ID (@IDs)
    {
        if(not defined $DWARF_Info{$ID}) {
            next;
        }
        
        if(my $Kind = $DWARF_Info{$ID}{"kind"})
        {
            if(defined $TypeType{$Kind}
            and not defined $Cache{"getTypeInfo"}{$ID})
            {
                getTypeInfo($ID);
            }
        }
    }
    
    foreach my $Tid (@IDs)
    {
        if(defined $DWARF_Info{$Tid}
        and defined $TypeInfo{$Tid})
        {
            my $Type = $TypeInfo{$Tid}{"Type"};
            
            if(not defined $TypeInfo{$Tid}{"Memb"})
            {
                if($Type=~/Struct|Class|Union|Enum/)
                {
                    if(my $Signature = $DWARF_Info{$Tid}{"signature"})
                    {
                        if(defined $TypeInfo{$Signature})
                        {
                            foreach my $Attr (keys(%{$TypeInfo{$Signature}}))
                            {
                                if(not defined $TypeInfo{$Tid}{$Attr}) {
                                    $TypeInfo{$Tid}{$Attr} = $TypeInfo{$Signature}{$Attr};
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    # delete types info
    foreach my $ID (@IDs)
    {
        if(not defined $DWARF_Info{$ID}) {
            next;
        }
        
        if(my $Kind = $DWARF_Info{$ID}{"kind"})
        {
            if(defined $TypeType{$Kind}) {
                delete($DWARF_Info{$ID});
            }
        }
    }
    
    foreach my $ID (@IDs)
    {
        if(not defined $DWARF_Info{$ID}) {
            next;
        }
        
        if($ID<0)
        { # imported
            next;
        }
        
        if($DWARF_Info{$ID}{"kind"} eq "prog"
        or $DWARF_Info{$ID}{"kind"} eq "variable")
        {
            getSymbolInfo($ID);
        }
    }
    
    if(defined $Compressed
    and not defined $AllUnits)
    {
        if(not $Partial)
        {
            foreach my $ID (@IDs)
            {
                if($DWARF_Info{$ID}{"kind"} ne "base_type") {
                    delete($DWARF_Info{$ID});
                }
            }
        }
        
        # free memory
        %TypeMember = ();
        %ArrayCount = ();
        %FuncParam = ();
        %TmplParam = ();
    }
    else
    {
        %DWARF_Info = ();
        
        # free memory
        %TypeMember = ();
        %ArrayCount = ();
        %FuncParam = ();
        %TmplParam = ();
        
        %Inheritance = ();
        %NameSpace = ();
        %SpecElem = ();
        %OrigElem = ();
        %ClassMethods = ();
        
        %LexicalId = ();
        
        $Cache{"getTypeInfo"} = {"1"=>1, "-1"=>1};
    }
    
    @IDs = ();
    @IDs_I = ();
}

sub selectSymbols()
{
    foreach my $ID (sort {$a<=>$b} keys(%SymbolInfo))
    {
        my $Symbol = $SymbolInfo{$ID}{"MnglName"};
        
        if(not $Symbol) {
            $Symbol = $SymbolInfo{$ID}{"ShortName"};
        }
        
        if(not $Symbol)
        {
            delete($SymbolInfo{$ID});
            next;
        }
        
        my $S = selectSymbol($SymbolInfo{$ID});
        
        if($S==0)
        {
            if(defined $AllSymbols)
            {
                if($SymbolInfo{$ID}{"External"})
                {
                    $S = 1;
                }
                else
                { # local
                    if(defined $DumpStatic) {
                        $S = 1;
                    }
                }
            }
        }
        
        if($S==0)
        {
            delete($SymbolInfo{$ID});
            next;
        }
        elsif(defined $PublicHeadersPath)
        {
            if(not selectPublic($Symbol, $ID)
            and (not defined $SymbolInfo{$ID}{"Alias"} or not selectPublic($SymbolInfo{$ID}{"Alias"}, $ID)))
            {
                delete($SymbolInfo{$ID});
                next;
            }
        }
        elsif(defined $KernelExport)
        {
            if(not defined $KSymTab{$Symbol})
            {
                delete($SymbolInfo{$ID});
                next;
            }
        }
        
        $SelectedSymbols{$ID} = $S;
        
        delete($SymbolInfo{$ID}{"External"});

        # add attributes
        if(defined $ExtraDump)
        {
            foreach my $Attr (keys(%{$SymbolAttribute{$Symbol}})) {
                $SymbolInfo{$ID}{$Attr} = $SymbolAttribute{$Symbol}{$Attr};
            }
        }
    }
}

sub completeTypes($)
{
    my $Name = $_[0];
    
    while($Name=~/T#(\d+)/)
    {
        my $Tid = $1;
        
        if(defined $TypeInfo{$Tid}
        and my $TName = $TypeInfo{$Tid}{"Name"})
        {
            $Name=~s/T#$Tid\b/$TName/g;
        }
        else
        {
            last;
        }
    }
    
    return formatName($Name, "T");
}

sub completeABI()
{
    # types
    my %Incomplete = ();
    my %Incomplete_TN = ();
    
    my @TIDs = sort {$a<=>$b} keys(%TypeInfo);
    
    if($AltDebugInfo) {
        @TIDs = sort {$b>0<=>$a>0} sort {abs($a)<=>abs($b)} @TIDs;
    }
    
    if(defined $Compressed
    and not defined $AllUnits)
    {
        foreach my $Tid (@TIDs)
        {
            my $TName = $TypeInfo{$Tid}{"Name"};
            if(index($TName, "#")!=-1)
            {
                $TypeInfo{$Tid}{"Name"} = completeTypes($TName);
                registerTName($Tid, $TypeInfo{$Tid}{"Name"}, $TypeInfo{$Tid}{"Type"});
            }
        }
    }
    
    foreach my $Tid (@TIDs)
    {
        my $Name = $TypeInfo{$Tid}{"Name"};
        my $Type = $TypeInfo{$Tid}{"Type"};
        
        if(not defined $SpecElem{$Tid}
        and not defined $Incomplete_TN{$Type}{$Name})
        {
            if(not defined $TypeInfo{$Tid}{"Size"})
            {
                if($Type=~/Struct|Class|Union|Enum/)
                {
                    $Incomplete{$Tid} = 1;
                }
            }
        }
        
        $Incomplete_TN{$Type}{$Name} = 1;
    }
    
    # free memory
    %Incomplete_TN = ();
    
    foreach my $Tid (sort {$a<=>$b} keys(%Incomplete))
    {
        my $Name = $TypeInfo{$Tid}{"Name"};
        my $Type = $TypeInfo{$Tid}{"Type"};
        
        my @Adv_TIDs = sort {$a<=>$b} keys(%{$TName_Tids{$Type}{$Name}});
    
        if($AltDebugInfo) {
            @Adv_TIDs = sort {$b>0<=>$a>0} sort {abs($a)<=>abs($b)} @Adv_TIDs;
        }
        
        foreach my $Tid_Adv (@Adv_TIDs)
        {
            if($Tid_Adv!=$Tid)
            {
                if(defined $SpecElem{$Tid_Adv}
                or defined $TypeInfo{$Tid_Adv}{"Size"})
                {
                    foreach my $Attr (keys(%{$TypeInfo{$Tid_Adv}}))
                    {
                        if(not defined $TypeInfo{$Tid}{$Attr})
                        {
                            if(ref($TypeInfo{$Tid_Adv}{$Attr}) eq "HASH") {
                                $TypeInfo{$Tid}{$Attr} = dclone($TypeInfo{$Tid_Adv}{$Attr});
                            }
                            else {
                                $TypeInfo{$Tid}{$Attr} = $TypeInfo{$Tid_Adv}{$Attr};
                            }
                            
                        }
                    }
                    last;
                }
            }
        }
    }
    
    # free memory
    %Incomplete = ();
    
    my %ReplacedAnon = ();
    
    foreach my $Tid (sort {$a<=>$b} keys(%TypeInfo))
    {
        if($TypeInfo{$Tid}{"Type"} eq "Typedef")
        {
            my $TN = $TypeInfo{$Tid}{"Name"};
            my $TL = $TypeInfo{$Tid}{"Line"};
            my $NS = $TypeInfo{$Tid}{"NameSpace"};
            
            if(my $BTid = $TypeInfo{$Tid}{"BaseType"})
            {
                my $BName = $TypeInfo{$BTid}{"Name"};
                my $BType = $TypeInfo{$BTid}{"Type"};
                
                if(defined $TypeInfo{$BTid}
                and $BName=~/\Aanon\-(\w+)\-/
                and $BType=~/Enum|Struct|Union/)
                {
                    $TypeInfo{$Tid} = dclone($TypeInfo{$BTid});
                    $TypeInfo{$Tid}{"Name"} = lc($TypeInfo{$BTid}{"Type"})." ".$TN;
                    $TypeInfo{$Tid}{"Line"} = $TL;
                    
                    my $Name = $TypeInfo{$Tid}{"Name"};
                    my $Type = $TypeInfo{$Tid}{"Type"};
                    
                    registerTName($Tid, $Name, $Type);
                    
                    if($NS) {
                        $TypeInfo{$Tid}{"NameSpace"} = $NS;
                    }
                    
                    $DeletedAnon{$BTid} = $Tid;
                    foreach my $BTid_S (keys(%{$TName_Tids{$BType}{$BName}})) {
                        $DeletedAnon{$BTid_S} = $Tid;
                    }
                }
            }
        }
        elsif($TypeInfo{$Tid}{"Type"} eq "Pointer")
        {
            if(my $BTid = $TypeInfo{$Tid}{"BaseType"})
            {
                my $To = undef;
                
                if(defined $DeletedAnon{$BTid}) {
                    $To = $DeletedAnon{$BTid};
                }
                elsif(defined $ReplacedAnon{$BTid}) {
                    $To = $BTid;
                }
                
                if($To)
                {
                    $TypeInfo{$Tid}{"BaseType"} = $To;
                    $TypeInfo{$Tid}{"Name"} = $TypeInfo{$To}{"Name"}."*";
                    
                    my $Name = $TypeInfo{$Tid}{"Name"};
                    my $Type = $TypeInfo{$Tid}{"Type"};
                    
                    $TName_Tid{$Type}{$Name} = $Tid;
                    $TName_Tids{$Type}{$Name}{$Tid} = 1;
                    
                    $ReplacedAnon{$Tid} = 1;
                }
            }
        }
        elsif($TypeInfo{$Tid}{"Type"} eq "Const")
        {
            if(my $BTid = $TypeInfo{$Tid}{"BaseType"})
            {
                my $To = undef;
                
                if(defined $DeletedAnon{$BTid}) {
                    $To = $DeletedAnon{$BTid};
                }
                elsif(defined $ReplacedAnon{$BTid}) {
                    $To = $BTid;
                }
                
                if($To)
                {
                    $TypeInfo{$Tid}{"BaseType"} = $To;
                    $TypeInfo{$Tid}{"Name"} = formatName($TypeInfo{$To}{"Name"}." const", "T");
                    
                    my $Name = $TypeInfo{$Tid}{"Name"};
                    my $Type = $TypeInfo{$Tid}{"Type"};
                    
                    $TName_Tid{$Type}{$Name} = $Tid;
                    $TName_Tids{$Type}{$Name}{$Tid} = 1;
                    
                    $ReplacedAnon{$Tid} = 1;
                }
            }
        }
    }
    
    foreach my $Tid (keys(%DeletedAnon))
    {
        my $TN = $TypeInfo{$Tid}{"Name"};
        my $TT = $TypeInfo{$Tid}{"Type"};
        
        delete($TName_Tid{$TT}{$TN});
        delete($TName_Tids{$TT}{$TN}{$Tid});
        
        if(my @TIDs = sort {$a<=>$b} keys(%{$TName_Tids{$TT}{$TN}}))
        { # minimal ID
            $TName_Tid{$TT}{$TN} = $TIDs[0];
        }
        
        delete($TypeInfo{$Tid});
    }
    
    # symbols
    foreach my $ID (sort {$a<=>$b} keys(%SymbolInfo))
    {
        if(defined $Compressed
        and not defined $AllUnits)
        { # replace late template arguments
            my $ShortName = $SymbolInfo{$ID}{"ShortName"};
            
            if(index($ShortName, "#")!=-1) {
                $SymbolInfo{$ID}{"ShortName"} = completeTypes($ShortName);
            }
        }
        
        # add missed c-tors
        if($SymbolInfo{$ID}{"Constructor"})
        {
            if($SymbolInfo{$ID}{"MnglName"}=~/(C[1-2])([EI]).+/)
            {
                my ($K1, $K2) = ($1, $2);
                foreach ("C1", "C2")
                {
                    if($K1 ne $_)
                    {
                        my $Name = $SymbolInfo{$ID}{"MnglName"};
                        $Name=~s/$K1$K2/$_$K2/;
                        
                        if(not defined $Mangled_ID{$Name}) {
                            $Mangled_ID{$Name} = cloneSymbol($ID, $Name);
                        }
                    }
                }
            }
        }
        
        # add missed d-tors
        if($SymbolInfo{$ID}{"Destructor"})
        {
            if($SymbolInfo{$ID}{"MnglName"}=~/(D[0-2])([EI]).+/)
            {
                my ($K1, $K2) = ($1, $2);
                foreach ("D0", "D1", "D2")
                {
                    if($K1 ne $_)
                    {
                        my $Name = $SymbolInfo{$ID}{"MnglName"};
                        $Name=~s/$K1$K2/$_$K2/;
                        
                        if(not defined $Mangled_ID{$Name}) {
                            $Mangled_ID{$Name} = cloneSymbol($ID, $Name);
                        }
                    }
                }
            }
        }
    }
    
    foreach my $ID (sort {$a<=>$b} keys(%SymbolInfo))
    {
        my $SInfo = $SymbolInfo{$ID};
        my $Symbol = $SInfo->{"MnglName"};
        my $Short = $SInfo->{"ShortName"};
        
        if(not $Symbol) {
            $Symbol = $Short;
        }
        
        if($LIB_LANG eq "C++")
        {
            if(not $SInfo->{"MnglName"})
            {
                if($SInfo->{"Artificial"}
                or index($Short, "~")==0)
                {
                    delete($SymbolInfo{$ID});
                    next;
                }
            }
        }
        
        if($SInfo->{"Class"}
        and not $SInfo->{"Data"}
        and not $SInfo->{"Constructor"}
        and not $SInfo->{"Destructor"}
        and not $SInfo->{"Virt"}
        and not $SInfo->{"PureVirt"})
        {
            if(not defined $SInfo->{"Param"}
            or $SInfo->{"Param"}{0}{"name"} ne "this")
            {
                if(not $ExtraDump or index($Symbol, "_ZTV")!=0)
                {
                    $SInfo->{"Static"} = 1;
                }
            }
        }
        
        if(not $SInfo->{"Return"})
        { # void
            if(not $SInfo->{"Constructor"}
            and not $SInfo->{"Destructor"})
            {
                $SInfo->{"Return"} = "1";
            }
        }
        
        if(not $SInfo->{"Header"})
        {
            if($SInfo->{"Class"})
            { # detect missed header by class
                if(defined $TypeInfo{$SInfo->{"Class"}}{"Header"}) {
                    $SInfo->{"Header"} = $TypeInfo{$SInfo->{"Class"}}{"Header"};
                }
            }
        }
        
        if(defined $PublicHeadersPath) {
            fixHeader($SInfo);
        }
        
        my $Header = $SInfo->{"Header"};
        
        if(defined $SInfo->{"Source"} and defined $SInfo->{"SourceLine"})
        {
            if(not defined $Header and not defined $SInfo->{"Line"})
            {
                $SInfo->{"Line"} = $SInfo->{"SourceLine"};
                delete($SInfo->{"SourceLine"});
            }
        }
        
        if(not $SInfo->{"Constructor"}
        and not $SInfo->{"Destructor"})
        {
            my $InLineDecl = delete($SInfo->{"DeclaredInlined"});
            
            my $Bind = undef;
            
            if(defined $Symbol_Bind{$Symbol}) {
                $Bind = $Symbol_Bind{$Symbol};
            }
            elsif(my $SVer = $SymVer{$Symbol})
            {
                if(defined $Symbol_Bind{$SVer}) {
                    $Bind = $Symbol_Bind{$SVer};
                }
            }
            
            if($Bind ne "GLOBAL" and $Bind ne "LOCAL")
            {
                # Not enough info in the DWARF dump
                if($Bind eq "WEAK")
                {
                    if($InLineDecl) {
                        $SInfo->{"InLine"} = 1;
                    }
                    else {
                        $SInfo->{"InLine"} = 2;
                    }
                }
                
                #if(not $SInfo->{"InLine"})
                #{
                #    if(defined $PublicHeadersPath)
                #    {
                #        if($Short and defined $Header
                #        and defined $PublicHeader{$Header})
                #        {
                #            if(defined $SymbolToHeader{$Short}
                #            and defined $SymbolToHeader{$Short}{$Header})
                #            {
                #                if($SymbolToHeader{$Short}{$Header} eq "function") {
                #                    $SInfo->{"InLine"} = 2;
                #                }
                #            }
                #        }
                #    }
                #}
            }
        }
        
        if(defined $SInfo->{"PureVirt"}) {
            delete($SInfo->{"InLine"});
        }
    }
}

sub warnPrivateType($$)
{
    my ($Name, $Note) = @_;
    
    if($Name=~/Private|Opaque/i)
    { # _GstClockPrivate
      # _Eo_Opaque
        return;
    }
    
    if($Name=~/(\A| )_/i)
    { # _GstBufferList
        return;
    }
    
    if($Name=~/_\Z/i)
    { # FT_RasterRec_
        return;
    }
    
    printMsg("WARNING", "Private data type \'".$Name."\' ($Note)");
}

sub warnPrivateSymbol($$)
{
    my ($Name, $Note) = @_;
    printMsg("WARNING", "Private symbol \'".$Name."\' ($Note)");
}

sub selectPublicType($)
{
    my $Tid = $_[0];
    
    if($TypeInfo{$Tid}{"Type"}!~/\A(Struct|Class|Union|Enum|Typedef)\Z/) {
        return 1;
    }
    
    my $TName = $TypeInfo{$Tid}{"Name"};
    $TName=~s/\A(struct|class|union|enum) //g;
    
    my $Header = getFilename($TypeInfo{$Tid}{"Header"});
    
    if($OBJ_LANG eq "C++"
    or index($TName, "anon-")==0) {
        return ($Header and defined $PublicHeader{$Header});
    }
    
    if($Header)
    {
        if(not defined $PublicHeader{$Header})
        {
            if(not defined $TypeToHeader{$TName}) {
                return 0;
            }
        }
        elsif($MixedHeaders)
        {
            if(not defined $TypeToHeader{$TName})
            {
                if(defined $Debug) {
                    warnPrivateType($TypeInfo{$Tid}{"Name"}, "NOT_FOUND");
                }
                return 0;
            }
        }
    }
    else
    {
        if(not defined $TypeToHeader{$TName})
        {
            # if(defined $Debug) {
            #     warnPrivateType($TypeInfo{$Tid}{"Name"}, "NO_HEADER");
            # }
            return 0;
        }
    }
    
    return 1;
}

sub selectPublic($$)
{
    my ($Symbol, $ID) = @_;

    if($ExtraDump)
    {
        if(index($Symbol, "_ZTV")==0)
        {
            return 1;
        }
    }

    my $Header = getFilename($SymbolInfo{$ID}{"Header"});
    
    if($OBJ_LANG eq "C++") {
        return ($Header and defined $PublicHeader{$Header});
    }
    
    if($Header)
    {
        if(not defined $PublicHeader{$Header})
        {
            if(not defined $SymbolToHeader{$Symbol}) {
                return 0;
            }
        }
        elsif($MixedHeaders)
        {
            if(not defined $SymbolToHeader{$Symbol})
            {
                if(defined $Debug) {
                    warnPrivateSymbol($Symbol, "NOT_FOUND");
                }
                return 0;
            }
        }
    }
    else
    {
        if(not defined $SymbolToHeader{$Symbol})
        {
            # if(defined $Debug) {
            #     warnPrivateSymbol($Symbol, "NO_HEADER");
            # }
            return 0;
        }
    }
    
    return 1;
}

sub add_VtableSymbols()
{
    foreach my $Symbol (sort {lc($a) cmp lc($b)} keys(%VTable_Class))
    {
        my $CName = $VTable_Class{$Symbol};
        my $ID = ++$GLOBAL_ID;

        $SymbolInfo{$ID}{"MnglName"} = $Symbol;

        # TODO: move VTable attr from TypeInfo to SymbolInfo

        if(not defined $TName_Tid{"Class"}{$CName}
        and not defined $TName_Tid{"Struct"}{$CName})
        { # create class
            my $ID_T = ++$GLOBAL_ID_T;

            $TName_Tid{"Class"}{$CName} = $ID_T;

            $TypeInfo{$ID_T}{"Type"} = "Class";
            $TypeInfo{$ID_T}{"Name"} = $CName;

            if($CName=~/\A([\w\:]+)\:\:/) {
                $TypeInfo{$ID_T}{"NameSpace"} = $1;
            }

            if(defined $VirtualTable{$CName}) {
                %{$TypeInfo{$ID_T}{"VTable"}} = %{$VirtualTable{$CName}};
            }
        }

        if(defined $TName_Tid{"Class"}{$CName}) {
            $SymbolInfo{$ID}{"Class"} = $TName_Tid{"Class"}{$CName};
        }
        elsif(defined $TName_Tid{"Struct"}{$CName}) {
            $SymbolInfo{$ID}{"Class"} = $TName_Tid{"Struct"}{$CName};
        }

        foreach my $Attr (keys(%{$SymbolAttribute{$Symbol}})) {
            $SymbolInfo{$ID}{$Attr} = $SymbolAttribute{$Symbol}{$Attr};
        }
    }
}

sub cloneSymbol($$)
{
    my ($ID, $Symbol) = @_;
    
    my $nID = undef;
    if(not defined $SymbolInfo{$ID + 1}) {
        $nID = $ID + 1;
    }
    else {
        $nID = ++$GLOBAL_ID;
    }
    foreach my $Attr (keys(%{$SymbolInfo{$ID}}))
    {
        if(ref($SymbolInfo{$ID}{$Attr}) eq "HASH") {
            $SymbolInfo{$nID}{$Attr} = dclone($SymbolInfo{$ID}{$Attr});
        }
        else {
            $SymbolInfo{$nID}{$Attr} = $SymbolInfo{$ID}{$Attr};
        }
    }
    $SymbolInfo{$nID}{"MnglName"} = $Symbol;
    return $nID;
}

sub selectSymbol($)
{
    my $SInfo = $_[0];
    
    my $MnglName = $SInfo->{"MnglName"};
    
    if(not $MnglName) {
        $MnglName = $SInfo->{"ShortName"};
    }
    
    if($SymbolsListPath
    and not $SymbolsList{$MnglName})
    {
        next;
    }
    
    my $Exp = 0;
    
    if($Library_Symbol{$TargetName}{$MnglName}
    or $Library_Symbol{$TargetName}{$SymVer{$MnglName}})
    {
        $Exp = 1;
    }
    
    if(my $Alias = $SInfo->{"Alias"})
    {
        if($Library_Symbol{$TargetName}{$Alias}
        or $Library_Symbol{$TargetName}{$SymVer{$Alias}})
        {
            $Exp = 1;
        }
    }
    
    if(not $Exp)
    {
        if(defined $Library_UndefSymbol{$TargetName}{$MnglName}
        or defined $Library_UndefSymbol{$TargetName}{$SymVer{$MnglName}})
        {
            return 0;
        }
        
        if($SInfo->{"Data"}
        or $SInfo->{"InLine"}
        or $SInfo->{"PureVirt"})
        {
            if(not $SInfo->{"External"})
            { # skip static
                return 0;
            }
            
            if(defined $BinOnly)
            { # data, inline, pure
                return 0;
            }
            elsif(not defined $SInfo->{"Header"})
            { # defined in source files
                return 0;
            }
            else {
                return 2;
            }
        }
        else {
            return 0;
        }
    }
    
    return 1;
}

sub formatName($$)
{ # type name correction
    if(defined $Cache{"formatName"}{$_[1]}{$_[0]}) {
        return $Cache{"formatName"}{$_[1]}{$_[0]};
    }
    
    my $N = $_[0];
    
    if($_[1] ne "S")
    {
        $N=~s/\A[ ]+//g;
        $N=~s/[ ]+\Z//g;
        $N=~s/[ ]{2,}/ /g;
    }
    
    $N=~s/[ ]*(\W)[ ]*/$1/g; # std::basic_string<char> const
    
    $N=~s/\b(const|volatile) ([\w\:]+)([\*&,>]|\Z)/$2 $1$3/g; # "const void" to "void const"
    
    $N=~s/\bvolatile const\b/const volatile/g;
    
    $N=~s/\b(long long|short|long) unsigned\b/unsigned $1/g;
    $N=~s/\b(short|long) int\b/$1/g;
    
    $N=~s/([\)\]])(const|volatile)\b/$1 $2/g;
    
    while($N=~s/>>/> >/g) {};
    
    if($_[1] eq "S")
    {
        if(index($N, "operator")!=-1) {
            $N=~s/\b(operator[ ]*)> >/$1>>/;
        }
    }
    
    $N=~s/,/, /g;
    
    if(defined $LambdaSupport)
    { # struct {lambda()}
        $N=~s/(\w)\{/$1 \{/g;
    }
    
    return ($Cache{"formatName"}{$_[1]}{$_[0]} = $N);
}

sub sepParams($)
{
    my $Str = $_[0];
    my @Parts = ();
    my %B = ( "("=>0, "<"=>0, ")"=>0, ">"=>0 );
    my $Part = 0;
    foreach my $Pos (0 .. length($Str) - 1)
    {
        my $S = substr($Str, $Pos, 1);
        if(defined $B{$S}) {
            $B{$S} += 1;
        }
        if($S eq "," and
        $B{"("}==$B{")"} and $B{"<"}==$B{">"}) {
            $Part += 1;
        }
        else {
            $Parts[$Part] .= $S;
        }
    }
    # remove spaces
    foreach (@Parts)
    {
        s/\A //g;
        s/ \Z//g;
    }
    return @Parts;
}

sub initFuncType($$$)
{
    my ($TInfo, $FTid, $Type) = @_;
    
    $TInfo->{"Type"} = $Type;
    
    if($TInfo->{"Return"} = $DWARF_Info{$FTid}{"type"}) {
        getTypeInfo($TInfo->{"Return"});
    }
    else
    { # void
        $TInfo->{"Return"} = "1";
    }
    delete($TInfo->{"BaseType"});
    
    my @Prms = ();
    my $PPos = 0;
    foreach my $Pos (sort {$a<=>$b} keys(%{$FuncParam{$FTid}}))
    {
        my $ParamId = $FuncParam{$FTid}{$Pos};
        my %PInfo = %{$DWARF_Info{$ParamId}};
        
        if(defined $PInfo{"art"})
        { # this
            next;
        }
        
        if(my $PTypeId = $PInfo{"type"})
        {
            $TInfo->{"Param"}{$PPos}{"type"} = $PTypeId;
            getTypeInfo($PTypeId);
            push(@Prms, $TypeInfo{$PTypeId}{"Name"});
        }
        
        $PPos += 1;
    }
    
    $TInfo->{"Name"} = $TypeInfo{$TInfo->{"Return"}}{"Name"};
    if($Type eq "FuncPtr") {
        $TInfo->{"Name"} .= "(*)";
    }
    $TInfo->{"Name"} .= "(".join(",", @Prms).")";
}

sub getShortName($)
{
    my $Name = $_[0];
    
    if(my $C = findCenter($Name, "<"))
    {
        return substr($Name, 0, $C);
    }
    
    return $Name;
}

sub getTKeys($)
{
    my @TParams = @{$_[0]};
    
    my @TKeys = ();
    
    foreach my $Pos (0 .. $#TParams)
    {
        my $TRef = $TParams[$Pos];
        
        if(defined $Compressed
        and not defined $AllUnits)
        { # not all types are available in the current compile unit
          # so handling them later
            my $Key = undef;
            
            if(defined $TRef->{"val"}) {
                $Key = computeValue($TRef);
            }
            elsif(defined $TRef->{"name"}) {
                $Key = $TRef->{"name"};
            }
            elsif(my $KeyT = $TRef->{"type"})
            {
                if(defined $TypeInfo{$KeyT}
                and my $TN = $TypeInfo{$KeyT}{"Name"})
                {
                    if(index($TN, "#")==-1) {
                        $Key = simpleName($TN);
                    }
                    else {
                        $Key = "T#".$KeyT;
                    }
                }
                else {
                    $Key = "T#".$KeyT;
                }
            }
            
            push(@TKeys, $Key);
        }
        else
        {
            my $Key = undef;
            
            if(defined $TRef->{"val"}) {
                $Key = computeValue($TRef);
            }
            elsif(my $KeyT = $TRef->{"type"}) {
                $Key = simpleName($TypeInfo{$KeyT}{"Name"});
            }
            else {
                $Key = $TRef->{"name"};
            }
            
            push(@TKeys, $Key);
        }
    }
    
    return @TKeys;
}

sub getTParams($$)
{
    my ($ID, $Name) = @_;
    
    my ($Short, $TParams) = ();
    
    if(defined $TmplParam{$ID})
    {
        $Short = getShortName($Name);
        $TParams = getTParams_I($ID);
        
        my ($AddShort, $AddParam) = ();
        
        foreach my $Pos (0 .. $#{$TParams})
        {
            my $P = $TParams->[$Pos];
            if(not defined $P->{"val"}
            and defined $P->{"type"})
            {
                my $TTid = $P->{"type"};
                if(not defined $TypeInfo{$TTid}
                or not $TypeInfo{$TTid}{"Name"})
                {
                    if(not $AddParam) {
                        ($AddShort, $AddParam) = parseTParams($Name);
                    }
                    
                    if($Pos<=$#{$AddParam}) {
                        $P->{"name"} = $AddParam->[$Pos]{"name"};
                    }
                }
            }
        }
    }
    else {
        ($Short, $TParams) = parseTParams($Name);
    }
    
    if(not $TParams) {
        return ();
    }
    
    return ($Short, $TParams);
}

sub getTParams_I($)
{
    my $ID = $_[0];
    
    my @TParams = ();
    
    foreach my $Pos (sort {$a<=>$b} keys(%{$TmplParam{$ID}}))
    {
        my $TTid = $TmplParam{$ID}{$Pos}{"type"};
        
        if($DWARF_Info{$TTid}{"kind"} eq "typedef") {
            $TTid = $DWARF_Info{$TTid}{"type"};
        }
        
        my $Val = undef;
        my $Key = undef;
        
        if(defined $TmplParam{$ID}{$Pos}{"value"}) {
            $Val = $TmplParam{$ID}{$Pos}{"value"};
        }
        
        if(defined $TmplParam{$ID}{$Pos}{"key"}) {
            $Key = $TmplParam{$ID}{$Pos}{"key"};
        }
        
        if($Pos>0)
        {
            if(defined $TmplParam{$ID}{$Pos}{"default"})
            {
                if($Key=~/\A(_Alloc|_Traits|_Compare)\Z/)
                {
                    next;
                }
            }
        }
        
        getTypeInfo($TTid);
        
        my %PInfo = (
            "type"=>$TTid,
            "key"=>$Key
        );
        
        if(defined $Val) {
            $PInfo{"val"} = $Val;
        }
        
        push(@TParams, \%PInfo);
    }
    
    return \@TParams;
}

sub parseTParams($)
{
    my $Name = $_[0];
    
    if(my $Cent = findCenter($Name, "<"))
    {
        my $TParams = substr($Name, $Cent);
        my $Short = substr($Name, 0, $Cent);
        
        $TParams=~s/\A<|>\Z//g;
        $TParams = simpleName($TParams);
        
        my @Params = sepParams($TParams);
        @Params = shortTParams($Short, \@Params);
        
        my @TParams = ();
        foreach my $Pos (0 .. $#Params)
        {
            my $Param = $Params[$Pos];
            if($Param=~/\A(.+>)(.*?)\Z/)
            {
                my ($Tm, $Suf) = ($1, $2);
                my ($Sh, $Prm) = parseTParams($Tm);
                
                if($Prm)
                {
                    my @Keys = ();
                    foreach my $P (@{$Prm}) {
                        push(@Keys, $P->{"name"});
                    }
                    
                    $Param = $Sh."<".join(", ", @Keys).">".$Suf;
                }
            }
            my %PInfo = (
                "name"=>formatName($Param, "T")
            );
            push(@TParams, \%PInfo);
        }
        
        return ($Short, \@TParams);
    }
    
    return (); # error
}

sub shortTParams($$)
{
    my $Short = $_[0];
    my @Params = @{$_[1]};
    
    # default arguments
    if($Short eq "std::vector")
    {
        if($#Params==1)
        {
            if($Params[1] eq "std::allocator<".$Params[0].">")
            { # std::vector<T, std::allocator<T> >
                splice(@Params, 1, 1);
            }
        }
    }
    elsif($Short eq "std::set")
    {
        if($#Params==2)
        {
            if($Params[1] eq "std::less<".$Params[0].">"
            and $Params[2] eq "std::allocator<".$Params[0].">")
            { # std::set<T, std::less<T>, std::allocator<T> >
                splice(@Params, 1, 2);
            }
        }
    }
    elsif($Short eq "std::basic_string")
    {
        if($#Params==2)
        {
            if($Params[1] eq "std::char_traits<".$Params[0].">"
            and $Params[2] eq "std::allocator<".$Params[0].">")
            { # std::basic_string<T, std::char_traits<T>, std::allocator<T> >
                splice(@Params, 1, 2);
            }
        }
    }
    elsif($Short eq "std::basic_ostream")
    {
        if($#Params==1)
        {
            if($Params[1] eq "std::char_traits<".$Params[0].">")
            { # std::basic_ostream<T, std::char_traits<T> >
                splice(@Params, 1, 1);
            }
        }
    }
    
    return @Params;
}

sub getTypeInfo($)
{
    my $ID = $_[0];
    
    if(not defined $DWARF_Info{$ID}) {
        return;
    }
    
    if(not keys(%{$DWARF_Info{$ID}}))
    {
        delete($DWARF_Info{$ID});
        return;
    }
    
    my $Kind = $DWARF_Info{$ID}{"kind"};
    
    if(defined $Cache{"getTypeInfo"}{$ID}) {
        return;
    }
    
    if(my $N = $NameSpace{$ID})
    {
        if($DWARF_Info{$N}{"kind"} eq "prog")
        { # local code
          # template instances are declared in the subprogram (constructor)
            my $Tmpl = 0;
            if(my $ObjP = $DWARF_Info{$N}{"objptr"})
            {
                while($DWARF_Info{$ObjP}{"type"}) {
                    $ObjP = $DWARF_Info{$ObjP}{"type"};
                }
                my $CName = $DWARF_Info{$ObjP}{"name"};
                $CName=~s/<.*//g;
                if($CName eq $DWARF_Info{$N}{"name"}) {
                    $Tmpl = 1;
                }
            }
            if(not $Tmpl)
            { # local types
                $LocalType{$ID} = 1;
            }
        }
        elsif($DWARF_Info{$N}{"kind"} eq "lexical_block")
        { # local code
            return;
        }
    }
    
    $Cache{"getTypeInfo"}{$ID} = 1;
    
    my %TInfo = ();
    
    $TInfo{"Type"} = $TypeType{$Kind};
    
    if(not $TInfo{"Type"})
    {
        if($DWARF_Info{$ID}{"kind"} eq "subroutine_type") {
            $TInfo{"Type"} = "Func";
        }
    }
    
    if($DWARF_Info{$ID}{"name"} eq "__unknown__")
    { # size of such type may vary
        delete($DWARF_Info{$ID}{"size"});
    }
    
    if(defined $SYS_CLANGV
    and $TInfo{"Type"} eq "FieldPtr")
    { # support for Clang
        if(my $T = $DWARF_Info{$ID}{"type"})
        {
            if($DWARF_Info{$T}{"kind"} eq "subroutine_type")
            {
                $TInfo{"Type"} = "MethodPtr";
                $DWARF_Info{$ID}{"pfn"} = $T;
                $DWARF_Info{$T}{"objptr"} = $DWARF_Info{$ID}{"container"};
            }
        }
    }
    
    my $RealType = $TInfo{"Type"};
    
    if(defined $ClassMethods{$ID})
    {
        if($TInfo{"Type"} eq "Struct") {
            $RealType = "Class";
        }
    }
    
    if($TInfo{"Type"} ne "Enum"
    and my $BaseType = $DWARF_Info{$ID}{"type"})
    {
        $TInfo{"BaseType"} = "$BaseType";
        
        if(defined $TypeType{$DWARF_Info{$BaseType}{"kind"}})
        {
            getTypeInfo($TInfo{"BaseType"});
            
            if(not defined $TypeInfo{$TInfo{"BaseType"}}
            or not $TypeInfo{$TInfo{"BaseType"}}{"Name"})
            { # local code
                delete($TypeInfo{$ID});
                return;
            }
        }
    }
    
    if($RealType eq "Class") {
        $TInfo{"Copied"} = 1; # will be changed in getSymbolInfo()
    }
    
    if(defined $TypeMember{$ID})
    {
        my $Unnamed = 0;
        foreach my $Pos (sort {$a<=>$b} keys(%{$TypeMember{$ID}}))
        {
            my $MemId = $TypeMember{$ID}{$Pos};
            my $MInfo = $DWARF_Info{$MemId};
            
            if(my $Name = $MInfo->{"name"})
            {
                if(index($Name, "_vptr.")==0)
                { # v-table pointer
                    $Name="_vptr";
                }
                $TInfo{"Memb"}{$Pos}{"name"} = $Name;
            }
            else
            {
                $TInfo{"Memb"}{$Pos}{"name"} = "unnamed".$Unnamed;
                $Unnamed += 1;
            }
            if($TInfo{"Type"} eq "Enum") {
                $TInfo{"Memb"}{$Pos}{"value"} = $MInfo->{"cval"};
            }
            else
            {
                $TInfo{"Memb"}{$Pos}{"type"} = $MInfo->{"type"};
                if(my $Access = $MInfo->{"access"})
                {
                    if($Access ne "public")
                    { # NOTE: default access of members in the ABI dump is "public"
                        $TInfo{"Memb"}{$Pos}{"access"} = $Access;
                    }
                }
                else
                { 
                    if($DWARF_Info{$ID}{"kind"} eq "class_type")
                    { # NOTE: default access of class members in the debug info is "private"
                        $TInfo{"Memb"}{$Pos}{"access"} = "private";
                    }
                    else
                    {
                        # NOTE: default access of struct members in the debug info is "public"
                    }
                }
                if($TInfo{"Type"} eq "Union") {
                    $TInfo{"Memb"}{$Pos}{"offset"} = "0";
                }
                elsif(defined $MInfo->{"mloc"}) {
                    $TInfo{"Memb"}{$Pos}{"offset"} = $MInfo->{"mloc"};
                }
            }
            
            if((my $BitSize = $MInfo->{"bit_size"}) ne "") {
                $TInfo{"Memb"}{$Pos}{"bitfield"} = $BitSize;
            }
        }
    }
    
    my $NS = $NameSpace{$ID};
    if(not $NS)
    {
        if(my $Sp = $DWARF_Info{$ID}{"spec"}) {
            $NS = $NameSpace{$Sp};
        }
    }
    
    if($NS and $DWARF_Info{$NS}{"kind"}=~/\A(class_type|structure_type)\Z/)
    { # member class
        if(my $Access = $DWARF_Info{$ID}{"access"})
        {
            if($Access ne "public")
            { # NOTE: default access of member classes in the ABI dump is "public"
                $TInfo{ucfirst($Access)} = 1;
            }
        }
        else
        {
            if($DWARF_Info{$NS}{"kind"} eq "class_type")
            {
                # NOTE: default access of member classes in the debug info is "private"
                $TInfo{"Private"} = 1;
            }
            else
            {
                # NOTE: default access to struct member classes in the debug info is "public"
            }
        }
    }
    else
    {
        if(my $Access = $DWARF_Info{$ID}{"access"})
        {
            if($Access ne "public")
            { # NOTE: default access of classes in the ABI dump is "public"
                $TInfo{ucfirst($Access)} = 1;
            }
        }
    }
    
    my $Size = $DWARF_Info{$ID}{"size"};
    if($Size ne "") {
        $TInfo{"Size"} = $Size;
    }
    
    setSource(\%TInfo, $ID);
    
    if(not $DWARF_Info{$ID}{"name"}
    and my $Spec = $DWARF_Info{$ID}{"spec"}) {
        $DWARF_Info{$ID}{"name"} = $DWARF_Info{$Spec}{"name"};
    }
    
    if($NS)
    {
        if($DWARF_Info{$NS}{"kind"} eq "namespace")
        {
            if(my $NS_F = completeNS($ID))
            {
                $TInfo{"NameSpace"} = $NS_F;
            }
        }
        elsif($DWARF_Info{$NS}{"kind"} eq "class_type"
        or $DWARF_Info{$NS}{"kind"} eq "structure_type")
        { # class
            getTypeInfo($NS);
            
            if(my $Sp = $SpecElem{$NS}) {
                getTypeInfo($Sp);
            }
            
            if($TypeInfo{$NS}{"Name"})
            {
                $TInfo{"NameSpace"} = $TypeInfo{$NS}{"Name"};
                $TInfo{"NameSpace"}=~s/\Astruct //;
            }
        }
    }
    
    if(my $Name = $DWARF_Info{$ID}{"name"})
    {
        $TInfo{"Name"} = $Name;
        
        if($TInfo{"NameSpace"}) {
            $TInfo{"Name"} = $TInfo{"NameSpace"}."::".$TInfo{"Name"};
        }
        
        if($TInfo{"Type"}=~/\A(Struct|Enum|Union)\Z/) {
            $TInfo{"Name"} = lc($TInfo{"Type"})." ".$TInfo{"Name"};
        }
    }
    
    if($TInfo{"Type"} eq "Struct")
    {
        if(not $TInfo{"Name"})
        {
            if(defined $TInfo{"Memb"}
            and $TInfo{"Memb"}{0}{"name"} eq "__pfn")
            { # __pfn and __delta
                my $Pfn = $TInfo{"Memb"}{0}{"type"};
                if(my $Pfn_B = $DWARF_Info{$Pfn}{"type"})
                {
                    if($DWARF_Info{$Pfn_B}{"kind"} eq "subroutine_type")
                    {
                        $TInfo{"Type"} = "MethodPtr";
                    }
                }
            }
        }
    }
    
    if($TInfo{"Type"}=~/Pointer|Ptr|Ref/)
    {
        if(not $TInfo{"Size"}) {
            $TInfo{"Size"} = $SYS_WORD;
        }
    }
    
    if($TInfo{"Type"} eq "Pointer")
    {
        if($DWARF_Info{$TInfo{"BaseType"}}{"kind"} eq "subroutine_type")
        {
            initFuncType(\%TInfo, $TInfo{"BaseType"}, "FuncPtr");
        }
    }
    elsif($TInfo{"Type"}=~/Typedef|Const|Volatile/)
    {
        if($DWARF_Info{$TInfo{"BaseType"}}{"kind"} eq "subroutine_type")
        {
            getTypeInfo($TInfo{"BaseType"});
        }
    }
    elsif($TInfo{"Type"} eq "Func")
    {
        initFuncType(\%TInfo, $ID, "Func");
    }
    elsif($TInfo{"Type"} eq "MethodPtr")
    {
        my $Pfn_B = undef;
        
        if(defined $TInfo{"Memb"}
        and $TInfo{"Memb"}{0}{"name"} eq "__pfn")
        {
            if(my $Pfn = $TInfo{"Memb"}{0}{"type"}) {
                $Pfn_B = $DWARF_Info{$Pfn}{"type"};
            }
        }
        else
        { # support for Clang
            $Pfn_B = $DWARF_Info{$ID}{"pfn"};
        }
        
        if($Pfn_B)
        {
            my @Prms = ();
            my $PPos = 0;
            foreach my $Pos (sort {$a<=>$b} keys(%{$FuncParam{$Pfn_B}}))
            {
                my $ParamId = $FuncParam{$Pfn_B}{$Pos};
                my %PInfo = %{$DWARF_Info{$ParamId}};
                
                if(defined $PInfo{"art"})
                { # this
                    next;
                }
                
                if(my $PTypeId = $PInfo{"type"})
                {
                    $TInfo{"Param"}{$PPos}{"type"} = $PTypeId;
                    getTypeInfo($PTypeId);
                    push(@Prms, $TypeInfo{$PTypeId}{"Name"});
                }
                
                $PPos += 1;
            }
            
            if(my $ClassId = $DWARF_Info{$Pfn_B}{"objptr"})
            {
                while($DWARF_Info{$ClassId}{"type"}) {
                    $ClassId = $DWARF_Info{$ClassId}{"type"};
                }
                $TInfo{"Class"} = $ClassId;
                getTypeInfo($TInfo{"Class"});
            }
            
            if($TInfo{"Return"} = $DWARF_Info{$Pfn_B}{"type"}) {
                getTypeInfo($TInfo{"Return"});
            }
            else
            { # void
                $TInfo{"Return"} = "1";
            }
            
            $TInfo{"Name"} = createMethodPtrName(\%TInfo);
            
            delete($TInfo{"BaseType"});
        }
    }
    elsif($TInfo{"Type"} eq "FieldPtr")
    {
        $TInfo{"Return"} = $TInfo{"BaseType"};
        delete($TInfo{"BaseType"});
        
        if(my $Class = $DWARF_Info{$ID}{"container"})
        {
            $TInfo{"Class"} = $Class;
            getTypeInfo($TInfo{"Class"});
            
            $TInfo{"Name"} = createFieldPtrName(\%TInfo);
        }
        
        $TInfo{"Size"} = $SYS_WORD;
    }
    elsif($TInfo{"Type"} eq "String")
    {
        $TInfo{"Type"} = "Pointer";
        $TInfo{"Name"} = "char*";
        $TInfo{"BaseType"} = $TName_Tid{"Intrinsic"}{"char"};
    }
    
    if(defined $Inheritance{$ID})
    {
        foreach my $Pos (sort {$a<=>$b} keys(%{$Inheritance{$ID}}))
        {
            if(my $BaseId = $Inheritance{$ID}{$Pos}{"id"})
            {
                if(my $E = $SpecElem{$BaseId}) {
                    $BaseId = $E;
                }
                
                $TInfo{"Base"}{$BaseId}{"pos"} = "$Pos";
                if(my $Access = $Inheritance{$ID}{$Pos}{"access"}) {
                    $TInfo{"Base"}{$BaseId}{"access"} = $Access;
                }
                if($Inheritance{$ID}{$Pos}{"virtual"}) {
                    $TInfo{"Base"}{$BaseId}{"virtual"} = 1;
                }
                
                $ClassChild{$BaseId}{$ID} = 1;
            }
        }
    }
    
    if(not $TInfo{"BaseType"})
    {
        if($TInfo{"Type"} eq "Pointer")
        {
            $TInfo{"Name"} = "void*";
            $TInfo{"BaseType"} = "1";
        }
        elsif($TInfo{"Type"} eq "Const")
        {
            $TInfo{"Name"} = "const void";
            $TInfo{"BaseType"} = "1";
        }
        elsif($TInfo{"Type"} eq "Volatile")
        {
            $TInfo{"Name"} = "volatile void";
            $TInfo{"BaseType"} = "1";
        }
        elsif($TInfo{"Type"} eq "Typedef")
        {
            $TInfo{"BaseType"} = "1";
        }
    }
    
    if(not $TInfo{"Name"}
    and $TInfo{"Type"} ne "Enum")
    {
        my $ID_ = $ID;
        my $BaseID = undef;
        my $Name = "";
        
        while($BaseID = $DWARF_Info{$ID_}{"type"})
        {
            my $Kind = $DWARF_Info{$ID_}{"kind"};
            if(my $Q = $Qual{$TypeType{$Kind}})
            {
                $Name = $Q.$Name;
                if($Q=~/\A\w/) {
                    $Name = " ".$Name;
                }
            }
            if(defined $TypeInfo{$BaseID}
            and $TypeInfo{$BaseID}{"Name"})
            {
                $Name = $TypeInfo{$BaseID}{"Name"}.$Name;
                last;
            }
            elsif(defined $DWARF_Info{$BaseID}
            and $DWARF_Info{$BaseID}{"name"})
            {
                $Name = $DWARF_Info{$BaseID}{"name"}.$Name;
                $ID_ = $BaseID;
            }
            elsif(defined $Compressed
            and not defined $AllUnits)
            {
                $Name = "T#".$BaseID.$Name;
                last;
            }
            else
            { # error
                last;
            }
        }
        
        if($Name) {
            $TInfo{"Name"} = $Name;
        }
        
        if($TInfo{"Type"} eq "Array")
        {
            if(my $Count = $ArrayCount{$ID})
            {
                $TInfo{"Name"} .= "[".$Count."]";
                if(my $BType = $TInfo{"BaseType"})
                {
                    if(my $BSize = $TypeInfo{$BType}{"Size"})
                    {
                        if(my $Size = $Count*$BSize)
                        {
                            $TInfo{"Size"} = "$Size";
                        }
                    }
                }
            }
            else
            {
                $TInfo{"Name"} .= "[]";
                $TInfo{"Size"} = $SYS_WORD;
            }
        }
        elsif($TInfo{"Type"} eq "Pointer")
        {
            if(my $BType = $TInfo{"BaseType"})
            {
                if($TypeInfo{$BType}{"Type"}=~/MethodPtr|FuncPtr/)
                { # void(GTestSuite::**)()
                  # int(**)(...)
                    if($TInfo{"Name"}=~s/\*\Z//) {
                        $TInfo{"Name"}=~s/\*(\))/\*\*$1/;
                    }
                }
            }
        }
    }
    
    if(my $Bid = $TInfo{"BaseType"})
    {
        if(not $TInfo{"Size"}
        and $TypeInfo{$Bid}{"Size"}) {
            $TInfo{"Size"} = $TypeInfo{$Bid}{"Size"};
        }
    }
    if($TInfo{"Name"}) {
        $TInfo{"Name"} = formatName($TInfo{"Name"}, "T");
    }
    
    if($TInfo{"Name"}=~/>\Z/)
    {
        my ($Short, $TParams) = getTParams($ID, $TInfo{"Name"});
        
        if($TParams)
        {
            delete($TInfo{"TParam"});
            
            foreach my $Pos (0 .. $#{$TParams}) {
                $TInfo{"TParam"}{$Pos} = $TParams->[$Pos];
            }
            
            my @TKeys = getTKeys($TParams);
            @TKeys = shortTParams($Short, \@TKeys);
            
            $TInfo{"Name"} = formatName($Short."<".join(", ", @TKeys).">", "T");
        }
    }
    
    if(not $TInfo{"Name"})
    {
        if($TInfo{"Type"}=~/\A(Class|Struct|Enum|Union)\Z/)
        {
            if($TInfo{"Header"}) {
                $TInfo{"Name"} = "anon-".lc($TInfo{"Type"})."-".$TInfo{"Header"}."-".$TInfo{"Line"};
            }
            elsif($TInfo{"Source"}) {
                $TInfo{"Name"} = "anon-".lc($TInfo{"Type"})."-".$TInfo{"Source"}."-".$TInfo{"SourceLine"};
            }
            else
            {
                if(not defined $TypeMember{$ID})
                {
                    if(not defined $ANON_TYPE_WARN{$TInfo{"Type"}})
                    {
                        printMsg("WARNING", "a \"".$TInfo{"Type"}."\" type with no attributes detected in the DWARF dump ($ID)");
                        $ANON_TYPE_WARN{$TInfo{"Type"}} = 1;
                    }
                    $TInfo{"Name"} = "anon-".lc($TInfo{"Type"});
                }
            }
            
            if($TInfo{"Name"} and $TInfo{"NameSpace"}) {
                $TInfo{"Name"} = $TInfo{"NameSpace"}."::".$TInfo{"Name"};
            }
        }
    }
    
    if($TInfo{"Name"}) {
        registerTName($ID, $TInfo{"Name"}, $TInfo{"Type"});
    }
    
    if(defined $TInfo{"Source"})
    {
        if(not defined $TInfo{"Header"})
        {
            $TInfo{"Line"} = $TInfo{"SourceLine"};
            delete($TInfo{"SourceLine"});
        }
    }
    
    foreach my $Attr (keys(%TInfo)) {
        $TypeInfo{$ID}{$Attr} = $TInfo{$Attr};
    }
    
    if(my $BASE_ID = $DWARF_Info{$ID}{"spec"})
    {
        foreach my $Attr (keys(%{$TypeInfo{$BASE_ID}}))
        {
            if($Attr ne "Type") {
                $TypeInfo{$ID}{$Attr} = $TypeInfo{$BASE_ID}{$Attr};
            }
        }
        
        foreach my $Attr (keys(%{$TypeInfo{$ID}})) {
            $TypeInfo{$BASE_ID}{$Attr} = $TypeInfo{$ID}{$Attr};
        }
        
        $TypeSpec{$ID} = $BASE_ID;
    }

    if(defined $ExtraDump)
    {
        if($ID>$GLOBAL_ID_T) {
            $GLOBAL_ID_T = $ID;
        }
    }

    # remove duplicates
    my $DId = undef;
    
    if(defined $DuplBaseType{$TInfo{"Name"}}) {
        $DId = $DuplBaseType{$TInfo{"Name"}};
    }
    else
    {
        my @DIds = sort {$a<=>$b} keys(%{$TName_Tids{$TInfo{"Type"}}{$TInfo{"Name"}}});
        
        if($#DIds>0)
        {
            foreach (@DIds)
            {
                if($_>0)
                {
                    $DId = $_;
                    last;
                }
            }
        }
    }
    
    if($DId and $DId ne $ID)
    {
        my $TInfo_D = $TypeInfo{$DId};
        if(keys(%{$TInfo_D})==keys(%{$TypeInfo{$ID}}))
        {
            $TypeInfo{$ID} = $TInfo_D;
            $DuplBaseType{$TInfo{"Name"}} = $DId;
        }
    }
}

sub registerTName($$$)
{
    my ($ID, $Name, $Type) = @_;
    
    if(not defined $TName_Tid{$Type}{$Name}
    or ($ID>0 and $ID<$TName_Tid{$Type}{$Name})
    or ($ID>0 and $TName_Tid{$Type}{$Name}<0))
    {
        $TName_Tid{$Type}{$Name} = "$ID";
    }
    $TName_Tids{$Type}{$Name}{$ID} = 1;
}

sub createMethodPtrName($)
{
    my $TInfo = $_[0];
    
    my @Prms = ();
    
    if($TInfo->{"Param"})
    {
        foreach my $Pos (sort {$a<=>$b} keys(%{$TInfo->{"Param"}})) {
            push(@Prms, $TypeInfo{$TInfo->{"Param"}{$Pos}{"type"}}{"Name"});
        }
    }
    
    my $TName = $TypeInfo{$TInfo->{"Return"}}{"Name"};
    $TName .= "(".$TypeInfo{$TInfo->{"Class"}}{"Name"}."::*)";
    $TName .= "(".join(",", @Prms).")";
    
    return $TName;
}

sub createFieldPtrName($)
{
    my $TInfo = $_[0];
    
    return $TypeInfo{$TInfo->{"Return"}}{"Name"}."(".$TypeInfo{$TInfo->{"Class"}}{"Name"}."::*)";
}

sub computeValue($)
{
    my $Ref = $_[0];
    
    my $TTid = $Ref->{"type"};
    my $TTName = $TypeInfo{$TTid}{"Name"};
    
    my $Val = $Ref->{"val"};
    
    if($TTName eq "bool")
    {
        if($Val eq "1") {
            $Val = "true";
        }
        elsif($Val eq "0") {
            $Val = "false";
        }
    }
    else
    {
        if($Val=~/\A\d+\Z/)
        {
            if(my $S = $ConstSuffix{$TTName}) {
                $Val .= $S;
            }
        }
    }
    
    return $Val;
}

sub setSource(@)
{
    my $R = shift(@_);
    my $ID = shift(@_);
    my $Target = undef;
    
    if(@_) {
        $Target = shift(@_);
    }
    
    my $File = $DWARF_Info{$ID}{"file"};
    my $Line = $DWARF_Info{$ID}{"line"};
    
    if(defined $File)
    {
        my $InfoName = undef;
        if(index($File, "(")!=-1)
        { # Support for new elfutils (Fedora 30)
            if($File=~s/\A(.+?)\s+\((\d+)\)/$1/) {
                $InfoName = $1;
            }
        }
        
        my $Name = undef;
        
        if($ID>=0) {
            $Name = $SourceFile{$DWARF_Info{$ID}{"unit"}}{$File};
        }
        else
        { # imported
            $Name = $SourceFile_Alt{0}{$File};
        }

        if(not $Name) {
            $Name = $InfoName;
        }
        
        if($Name=~/\.($HEADER_EXT)\Z/i
        or index($Name, ".")==-1)
        { # header
            if(not defined $Target or $Target eq "Header")
            {
                $R->{"Header"} = $Name;
                if(defined $Line) {
                    $R->{"Line"} = $Line;
                }
            }
            elsif($Target eq "Line")
            {
                if(defined $Line and $R->{"Header"} eq $Name) {
                    $R->{"Line"} = $Line;
                }
            }
        }
        elsif(index($Name, "<built-in>")==-1)
        { # source
            if(not defined $Target or $Target eq "Source")
            {
                $R->{"Source"} = $Name;
                if(defined $Line) {
                    $R->{"SourceLine"} = $Line;
                }
            }
        }
    }
}

sub skipSymbol($)
{
    if($SkipCxx and not $STDCXX_TARGET)
    {
        if($_[0]=~/\A(_ZS|_ZNS|_ZNKS|_ZN9__gnu_cxx|_ZNK9__gnu_cxx|_ZTIS|_ZTSS|_Zd|_Zn)/)
        { # stdc++ symbols
            return 1;
        }
    }
    return 0;
}

sub findCenter($$)
{
    my ($Name, $Target) = @_;
    my %B = ( "("=>0, "<"=>0, ")"=>0, ">"=>0 );
    foreach my $Pos (0 .. length($Name)-1)
    {
        my $S = substr($Name, length($Name)-1-$Pos, 1);
        if(defined $B{$S}) {
            $B{$S}+=1;
        }
        if($S eq $Target)
        {
            if($B{"("}==$B{")"}
            and $B{"<"}==$B{">"}) {
                return length($Name)-1-$Pos;
            }
        }
    }
    return 0;
}

sub isExternal($)
{
    my $ID = $_[0];
    
    if($DWARF_Info{$ID}{"ext"}) {
        return 1;
    }
    elsif(my $Spec = $DWARF_Info{$ID}{"spec"})
    {
        if($DWARF_Info{$Spec}{"ext"}) {
            return 1;
        }
    }
    
    return 0;
}

sub symByAddr($)
{
    my $Loc = $_[0];
    
    my ($Addr, $Sect) = ("", "");
    if($Loc=~/\+(.+)/)
    {
        $Addr = $1;
        if(not $Addr=~s/\A0x//)
        {
            $Addr=~s/\A00//;
        }
    }
    if($Loc=~/([\w\.]+)\+/) {
        $Sect = $1;
    }
    
    if($Addr ne "")
    {
        foreach ($Sect, "")
        {
            if(defined $SymbolTable{$_}{$Addr})
            {
                if(my @Symbols = sort keys(%{$SymbolTable{$_}{$Addr}})) {
                    return $Symbols[0];
                }
            }
        }
    }
    
    return undef;
}

sub getMangled($)
{
    my $ID = $_[0];
    
    if(not defined $AddrToName)
    {
        if(my $Link = $DWARF_Info{$ID}{"linkage"})
        {
            return $Link;
        }
    }
    
    if(my $Low_Pc = $DWARF_Info{$ID}{"low_pc"})
    {
        if($Low_Pc=~/<([\w\@\.]+)>/) {
            return $1;
        }
        else
        {
            if(my $Symbol = symByAddr($Low_Pc)) {
                return $Symbol;
            }
        }
    }
    
    if(my $Loc = $DWARF_Info{$ID}{"location"})
    {
        if($Loc=~/<([\w\@\.]+)>/) {
            return $1;
        }
        else
        {
            if(my $Symbol = symByAddr($Loc)) {
                return $Symbol;
            }
        }
    }
    
    if(my $Link = $DWARF_Info{$ID}{"linkage"})
    {
        return $Link;
    }
    
    return undef;
}

sub completeNS($)
{
    my $ID = $_[0];
    
    my $NS = undef;
    my $ID_ = $ID;
    my @NSs = ();
    
    while($NS = $NameSpace{$ID_}
    or $NS = $NameSpace{$DWARF_Info{$ID_}{"spec"}})
    {
        if(my $N = $DWARF_Info{$NS}{"name"}) {
            push(@NSs, $N);
        }
        $ID_ = $NS;
    }
    
    if(@NSs)
    {
        my $N = join("::", reverse(@NSs));
        $NestedNameSpaces{$N} = 1;
        return $N;
    }
    
    return undef;
}

sub getSymbolInfo($)
{
    my $ID = $_[0];
    
    if(my $N = $NameSpace{$ID})
    {
        if($DWARF_Info{$N}{"kind"} eq "lexical_block"
        or $DWARF_Info{$N}{"kind"} eq "prog")
        { # local variables
            return;
        }
    }
    
    my $Orig = $DWARF_Info{$ID}{"orig"};
    my $Container = undef;
    
    if(defined $DWARF_Info{$ID}{"container"}) {
        $Container = $DWARF_Info{$ID}{"container"};
    }
    elsif(defined $DWARF_Info{$Orig}{"container"}) {
        $Container = $DWARF_Info{$Orig}{"container"};
    }
    
    if(defined $Container
    and defined $LexicalId{$Container})
    { # local functions
        return;
    }
    
    if(my $Loc = $DWARF_Info{$ID}{"location"})
    {
        if($Loc=~/ reg\d+\Z/)
        { # local variables
            return;
        }
    }
    
    my $ShortName = $DWARF_Info{$ID}{"name"};
    my $MnglName = getMangled($ID);
    
    if(not $MnglName)
    {
        if(my $Sp = $SpecElem{$ID})
        {
            $MnglName = getMangled($Sp);
            
            if(not $MnglName)
            {
                if(my $OrigSp = $OrigElem{$Sp})
                {
                    $MnglName = getMangled($OrigSp);
                }
            }
        }
    }
    
    if(not $MnglName)
    {
        if($ShortName!~/\W/)
        { # C-func
            $MnglName = $ShortName;
        }
    }
    
    if(defined $Compressed
    and not defined $AllUnits)
    {
        if(not $MnglName)
        {
            if(not $Partial) {
                return;
            }
        }
    }
    else
    {
        if(not $MnglName) {
            return;
        }
    }
    
    if(index($MnglName, "\@")!=-1) {
        $MnglName=~s/([\@]+.*?)\Z//;
    }
    
    if($MnglName=~/\W/)
    { # unmangled operators, etc.
      # foo.part.14
      # bar.isra.15
        return;
    }
    
    if(skipSymbol($MnglName)) {
        return;
    }
    
    my %SInfo = ();
    
    if($DWARF_Info{$ID}{"kind"} eq "variable")
    { # global data
        $SInfo{"Data"} = 1;
    }
    
    if($ShortName) {
        $SInfo{"ShortName"} = $ShortName;
    }
    $SInfo{"MnglName"} = $MnglName;
    
    if($MnglName and my $OLD_ID = $Mangled_ID{$MnglName})
    { # duplicates
        if(not defined $SymbolInfo{$OLD_ID}{"Header"}) {
            setSource($SymbolInfo{$OLD_ID}, $ID, "Header");
        }
        
        if(not defined $SymbolInfo{$OLD_ID}{"Line"}) {
            setSource($SymbolInfo{$OLD_ID}, $ID, "Line");
        }
        
        if(not defined $SymbolInfo{$OLD_ID}{"Source"}) {
            setSource($SymbolInfo{$OLD_ID}, $ID, "Source");
        }
        
        if(not defined $SymbolInfo{$OLD_ID}{"ShortName"}
        and $ShortName) {
            $SymbolInfo{$OLD_ID}{"ShortName"} = $ShortName;
        }
        
        if(defined $DWARF_Info{$OLD_ID}{"low_pc"}
        or not defined $DWARF_Info{$ID}{"low_pc"})
        {
            if(defined $Checked_Spec{$MnglName}
            or not $DWARF_Info{$ID}{"spec"})
            {
                if(defined $SymbolInfo{$OLD_ID}{"Param"}
                or not defined $FuncParam{$ID})
                {
                    if(defined $SymbolInfo{$OLD_ID}{"Return"}
                    or not defined $DWARF_Info{$ID}{"type"})
                    {
                        if(not defined $SpecElem{$ID}
                        and not defined $OrigElem{$ID}) {
                            delete($DWARF_Info{$ID});
                        }
                        return;
                    }
                }
            }
        }
    }
    
    if($ShortName)
    {
        if($MnglName eq $ShortName)
        {
            delete($SInfo{"MnglName"});
            $MnglName = $ShortName;
        }
        elsif($MnglName
        and index($MnglName, "_Z")!=0)
        {
            if($SInfo{"ShortName"})
            {
                if(index($SInfo{"ShortName"}, ".")==-1) {
                    $SInfo{"Alias"} = $SInfo{"ShortName"};
                }
                $SInfo{"ShortName"} = $SInfo{"MnglName"};
            }
            
            delete($SInfo{"MnglName"});
            $MnglName = $ShortName;
        }
    }
    else
    {
        if(index($MnglName, "_Z")!=0)
        {
            $SInfo{"ShortName"} = $SInfo{"MnglName"};
            delete($SInfo{"MnglName"});
        }
    }
    
    if(isExternal($ID)) {
        $SInfo{"External"} = 1;
    }
    
    if($Orig)
    {
        if(isExternal($Orig)) {
            $SInfo{"External"} = 1;
        }
    }
    
    if(index($MnglName, "_ZNVK")==0)
    {
        $SInfo{"Const"} = 1;
        $SInfo{"Volatile"} = 1;
    }
    elsif(index($MnglName, "_ZNV")==0) {
        $SInfo{"Volatile"} = 1;
    }
    elsif(index($MnglName, "_ZNK")==0) {
        $SInfo{"Const"} = 1;
    }
    
    if($DWARF_Info{$ID}{"art"}) {
        $SInfo{"Artificial"} = 1;
    }
    
    my ($C, $D) = ();
    
    if($MnglName=~/(C[1-4])[EI].+/)
    {
        $C = $1;
        $SInfo{"Constructor"} = 1;
    }
    
    if($MnglName=~/(D[0-4])[EI].+/)
    {
        $D = $1;
        $SInfo{"Destructor"} = 1;
    }
    
    if($C or $D)
    {
        if($Orig)
        {
            if(my $InLine = $DWARF_Info{$Orig}{"inline"})
            {
                if(index($InLine, "declared_not_inlined")==0)
                {
                    $SInfo{"InLine"} = 1;
                    $SInfo{"Artificial"} = 1;
                }
            }
            
            setSource(\%SInfo, $Orig);
            
            if(my $Spec = $DWARF_Info{$Orig}{"spec"})
            {
                setSource(\%SInfo, $Spec);
                
                $SInfo{"ShortName"} = $DWARF_Info{$Spec}{"name"};
                if($D) {
                    $SInfo{"ShortName"}=~s/\A\~//g;
                }
                
                if(my $Class = $NameSpace{$Spec}) {
                    $SInfo{"Class"} = $Class;
                }
                
                if(my $Virt = $DWARF_Info{$Spec}{"virt"})
                {
                    if(index($Virt, "virtual")!=-1) {
                        $SInfo{"Virt"} = 1;
                    }
                }
                
                if(my $Access = $DWARF_Info{$Spec}{"access"})
                {
                    if($Access ne "public")
                    { # default access of methods in the ABI dump is "public"
                        $SInfo{ucfirst($Access)} = 1;
                    }
                }
                else
                { # NOTE: default access of class methods in the debug info is "private"
                    if($TypeInfo{$SInfo{"Class"}}{"Type"} eq "Class")
                    {
                        $SInfo{"Private"} = 1;
                    }
                }
                
                if(not defined $Compressed
                or defined $AllUnits)
                {
                    # clean origin
                    delete($SymbolInfo{$Spec});
                }
            }
        }
    }
    else
    {
        if(my $InLine = $DWARF_Info{$ID}{"inline"})
        {
            if(index($InLine, "declared_inlined")==0) {
                $SInfo{"DeclaredInlined"} = 1;
            }
        }
    }
    
    if(defined $AddrToName)
    {
        if(not $SInfo{"Alias"}
        and not $SInfo{"Constructor"}
        and not $SInfo{"Destructor"})
        {
            if(my $Linkage = $DWARF_Info{$ID}{"linkage"})
            {
                if($Linkage ne $MnglName) {
                    $SInfo{"Alias"} = $Linkage;
                }
            }
        }
    }
    
    if($SInfo{"Data"})
    {
        if(my $Spec = $DWARF_Info{$ID}{"spec"})
        {
            if($DWARF_Info{$Spec}{"kind"} eq "member")
            {
                setSource(\%SInfo, $Spec);
                $SInfo{"ShortName"} = $DWARF_Info{$Spec}{"name"};
                
                if(my $NSp = $NameSpace{$Spec})
                {
                    if($DWARF_Info{$NSp}{"kind"} eq "namespace") {
                        $SInfo{"NameSpace"} = completeNS($Spec);
                    }
                    else {
                        $SInfo{"Class"} = $NSp;
                    }
                }
            }
        }
    }
    
    if(my $Access = $DWARF_Info{$ID}{"access"})
    {
        if($Access ne "public")
        { # default access of methods in the ABI dump is "public"
            $SInfo{ucfirst($Access)} = 1;
        }
    }
    elsif(not $DWARF_Info{$ID}{"spec"}
    and not $Orig)
    {
        if(my $NS = $NameSpace{$ID})
        {
            if(defined $TypeInfo{$NS})
            { # NOTE: default access of class methods in the debug info is "private"
                if($TypeInfo{$NS}{"Type"} eq "Class")
                {
                    $SInfo{"Private"} = 1;
                }
            }
        }
    }
    
    if(my $Class = $DWARF_Info{$ID}{"container"})
    {
        $SInfo{"Class"} = $Class;
    }
    
    if(my $NS = $NameSpace{$ID})
    {
        if($DWARF_Info{$NS}{"kind"} eq "namespace") {
            $SInfo{"NameSpace"} = completeNS($ID);
        }
        else {
            $SInfo{"Class"} = $NS;
        }
    }
    
    if($SInfo{"Class"} and $MnglName
    and index($MnglName, "_Z")!=0) {
        return;
    }
    
    if(my $Return = $DWARF_Info{$ID}{"type"})
    {
        $SInfo{"Return"} = $Return;
    }
    if(my $Spec = $DWARF_Info{$ID}{"spec"})
    {
        if(not $DWARF_Info{$ID}{"type"})
        {
            if(my $SpRet = $DWARF_Info{$Spec}{"type"}) {
                $SInfo{"Return"} = $SpRet;
            }
        }
        if(my $Value = $DWARF_Info{$Spec}{"cval"})
        {
            if($Value=~/ block:\s*(.*?)\Z/) {
                $Value = $1;
            }
            $SInfo{"Value"} = $Value;
        }
    }
    
    if($SInfo{"ShortName"}=~/>\Z/)
    { # foo<T1, T2, ...>
        my ($Short, $TParams) = getTParams($ID, $SInfo{"ShortName"});
        
        if($TParams)
        {
            foreach my $Pos (0 .. $#{$TParams}) {
                $SInfo{"TParam"}{$Pos} = $TParams->[$Pos];
            }
            
            my @TKeys = getTKeys($TParams);
            
            $SInfo{"ShortName"} = $Short.formatName("<".join(", ", @TKeys).">", "T");
        }
    }
    elsif($SInfo{"ShortName"}=~/\Aoperator (\w.*)\Z/)
    { # operator type<T1>::name
        $SInfo{"ShortName"} = "operator ".simpleName($1);
    }
    
    if(my $Virt = $DWARF_Info{$ID}{"virt"})
    {
        if(index($Virt, "virtual")!=-1)
        {
            if($D or defined $SpecElem{$ID}) {
                $SInfo{"Virt"} = 1;
            }
            else {
                $SInfo{"PureVirt"} = 1;
            }
        }
        
        if((my $VirtPos = $DWARF_Info{$ID}{"vloc"}) ne "")
        {
            $SInfo{"VirtPos"} = $VirtPos;
        }
    }
    
    setSource(\%SInfo, $ID);
    
    if(not $SInfo{"Header"})
    {
        if($SInfo{"Class"})
        { # detect missed header by class
            if(defined $TypeInfo{$SInfo{"Class"}}{"Header"}) {
                $SInfo{"Header"} = $TypeInfo{$SInfo{"Class"}}{"Header"};
            }
        }
    }
    
    my $PPos = 0;
    
    foreach my $Pos (sort {$a<=>$b} keys(%{$FuncParam{$ID}}))
    {
        my $ParamId = $FuncParam{$ID}{$Pos};
        my $Offset = undef;
        my %Regs = ();
        
        if(my $Sp = $SpecElem{$ID})
        {
            if(defined $FuncParam{$Sp}) {
                $ParamId = $FuncParam{$Sp}{$Pos};
            }
        }
        
        if((my $Loc = $DWARF_Info{$ParamId}{"location"}) ne "") {
            $Offset = $Loc;
        }
        elsif((my $LL = $DWARF_Info{$ParamId}{"location_list"}) ne "")
        {
            if(my $L = $DebugLoc{$LL})
            {
                if($L=~/reg(\d+)/) {
                    $Regs{0} = $RegName{$1};
                }
                elsif($L=~/fbreg\s+(-?\w+)\Z/) {
                    $Offset = $1;
                }
            }
            elsif(not defined $DebugLoc{$LL})
            { # invalid debug_loc
                if(not $InvalidDebugLoc)
                {
                    printMsg("ERROR", "invalid debug_loc section of object, please fix your elf utils");
                    $InvalidDebugLoc = 1;
                }
            }
        }
        elsif(defined $ExtraDump)
        {
            my $Piece = 0;
            foreach my $P (sort {int($a)<=>int($b)} keys(%{$FullLoc{$ParamId}}))
            {
                my $L = $FullLoc{$ParamId}{$P};

                if($L=~/piece (\d+)/) {
                    $Piece = $1;
                }
                elsif($L=~/stack_value/)
                {
                    # Nothing to do
                }
                elsif($L=~/reg(\d+)/)
                {
                    $Regs{$Piece} = $RegName{$1};
                }
                else
                {
                    # Error
                }
            }
        }
        elsif(defined $DWARF_Info{$ParamId}{"register"})
        {
            my $R = $DWARF_Info{$ParamId}{"register"};
            $Regs{0} = $RegName{$R};
        }
        
        if(my $OrigP = $DWARF_Info{$ParamId}{"orig"}) {
            $ParamId = $OrigP;
        }
        
        if(not defined $DWARF_Info{$ParamId})
        { # this is probably a lexical block
            printMsg("ERROR", "incomplete info for symbol $ID");
            return;
        }
        
        my %PInfo = %{$DWARF_Info{$ParamId}};
        
        if(defined $PInfo{"name"}
        and ($PInfo{"name"} eq "__in_chrg" or $PInfo{"name"} eq "__vtt_parm")) {
            next;
        }
        
        if(defined $Offset
        and not defined $IncompatibleOpt)
        {
            if($SYS_ARCH eq "x86_64")
            {
                if($Offset<0) { # debug-info failure
                    $Offset = undef;
                }
            }
            
            if(defined $Offset) {
                $SInfo{"Param"}{$Pos}{"offset"} = "$Offset";
            }
        }
        
        if($TypeInfo{$PInfo{"type"}}{"Type"} eq "Const")
        {
            if(my $BTid = $TypeInfo{$PInfo{"type"}}{"BaseType"})
            {
                if($TypeInfo{$BTid}{"Type"} eq "Ref")
                { # const&const -> const&
                    $PInfo{"type"} = $BTid;
                }
            }
        }
        
        $SInfo{"Param"}{$Pos}{"type"} = $PInfo{"type"};
        
        if(defined $PInfo{"name"}) {
            $SInfo{"Param"}{$Pos}{"name"} = $PInfo{"name"};
        }
        elsif($TypeInfo{$PInfo{"type"}}{"Name"} ne "...") {
            $SInfo{"Param"}{$Pos}{"name"} = "p".($PPos+1);
        }
        
        if(defined $RegisterIdenfificationIsReliable
        and my @R = keys(%Regs)
        and not defined $IncompatibleOpt)
        {
            if(defined $ExtraDump)
            {
                # FIXME: 0+8, 1+16, etc. (for partially distributed parameters)
                foreach my $RP (@R)
                {
                    my $O = $Pos;
                    if($RP) {
                        $O .= "+".$RP;
                    }

                    $SInfo{"Reg"}{$O} = $Regs{$RP};
                }
            }
            else
            {
                $SInfo{"Reg"}{$Pos} = $Regs{$R[0]};
            }
        }
        
        if($DWARF_Info{$ParamId}{"art"} and $Pos==0)
        {
            if($SInfo{"Param"}{$Pos}{"name"} eq "p1") {
                $SInfo{"Param"}{$Pos}{"name"} = "this";
            }
        }
        
        if($SInfo{"Param"}{$Pos}{"name"} ne "this")
        { # this, p1, p2, etc.
            $PPos += 1;
        }
    }
    
    if($SInfo{"Constructor"} and not $SInfo{"InLine"}
    and $SInfo{"Class"}) {
        delete($TypeInfo{$SInfo{"Class"}}{"Copied"});
    }
    
    my $BASE_ID = undef;
    
    if($MnglName) {
        $BASE_ID = $Mangled_ID{$MnglName};
    }
    
    if(defined $Compressed
    and not defined $AllUnits)
    {
        if($MnglName and not $BASE_ID)
        {
            my $B_ID = undef;
            if(my $Sp = $DWARF_Info{$ID}{"spec"}) {
                $B_ID = $Sp;
            }
            elsif($Orig)
            {
                if(my $OrigSp = $DWARF_Info{$Orig}{"spec"}) {
                    $B_ID = $OrigSp;
                }
            }
            
            if($B_ID and $B_ID>0)
            { # negative ones are not used for symbols
                $BASE_ID = $B_ID;
                
                if($MnglName) {
                    $Mangled_ID{$MnglName} = $BASE_ID;
                }
                
                # drop old mangled name
                delete($Mangled_ID{$SymbolInfo{$BASE_ID}{"MnglName"}});
            }
        }
    }
    
    if($BASE_ID)
    {
        if(defined $SInfo{"Param"})
        {
            if($MnglName and index($MnglName, "_Z")!=0)
            {
                my $DifferentParams = (keys(%{$SInfo{"Param"}})!=keys(%{$SymbolInfo{$BASE_ID}{"Param"}}));
                if($DifferentParams or keys(%{$SInfo{"Param"}})==1)
                { # different symbols with the same name
                    if(defined $SInfo{"Param"}
                    and $SInfo{"Param"}{0}{"type"}=="-1")
                    { # missed signature (...)
                        return;
                    }
                }
                
                if($DifferentParams)
                { # take the last one
                    delete($SymbolInfo{$BASE_ID});
                }
            }
        }
        
        $ID = $BASE_ID;
        
        if(defined $SymbolInfo{$ID}{"PureVirt"})
        { # if the specification of a symbol is located in other compile unit
            delete($SymbolInfo{$ID}{"PureVirt"});
            $SymbolInfo{$ID}{"Virt"} = 1;
        }
    }
    
    if($MnglName) {
        $Mangled_ID{$MnglName} = $ID;
    }
    
    if($DWARF_Info{$ID}{"spec"}) {
        $Checked_Spec{$MnglName} = 1;
    }
    
    my $MixedSymbols = 0;
    
    if(defined $SInfo{"Param"}
    and defined $SymbolInfo{$ID}
    and defined $SymbolInfo{$ID}{"Param"})
    {
        foreach my $K1 (keys(%{$SInfo{"Param"}}))
        {
            if(defined $SymbolInfo{$ID}{"Param"}{$K1})
            {
                if($SInfo{"Param"}{$K1}{"type"} eq "-1"
                and $SymbolInfo{$ID}{"Param"}{$K1}{"type"} ne "-1")
                {
                    $MixedSymbols = 1;
                    last;
                }
            }
        }
    }
    
    if(not $MixedSymbols)
    {
        foreach my $Attr (keys(%SInfo))
        {
            if(ref($SInfo{$Attr}) eq "HASH")
            {
                my @Prms = keys(%{$SInfo{$Attr}});
                
                if($Attr eq "Param" and @Prms
                and defined $SymbolInfo{$ID}
                and defined $SymbolInfo{$ID}{$Attr})
                {
                    my $Clear = 0;
                    
                    if(keys(%{$SymbolInfo{$ID}{$Attr}})!=$#Prms+1)
                    { # do not mix parameters of different symbols
                        $Clear = 1;
                    }
                    
                    if($Clear) {
                        $SymbolInfo{$ID}{$Attr} = {};
                    }
                }
                
                foreach my $K1 (keys(%{$SInfo{$Attr}}))
                {
                    if(ref($SInfo{$Attr}{$K1}) eq "HASH")
                    {
                        foreach my $K2 (keys(%{$SInfo{$Attr}{$K1}}))
                        {
                            $SymbolInfo{$ID}{$Attr}{$K1}{$K2} = $SInfo{$Attr}{$K1}{$K2};
                        }
                    }
                    else {
                        $SymbolInfo{$ID}{$Attr}{$K1} = $SInfo{$Attr}{$K1};
                    }
                }
            }
            else
            {
                $SymbolInfo{$ID}{$Attr} = $SInfo{$Attr};
            }
        }
    }
    
    if($ID>$GLOBAL_ID) {
        $GLOBAL_ID = $ID;
    }
}

sub fixHeader($)
{
    my $SInfo = $_[0];
    
    if(not $SInfo->{"Header"}
    or ($SInfo->{"External"} and not defined $PublicHeader{$SInfo->{"Header"}}))
    {
        if($SInfo->{"MnglName"} and defined $SymbolToHeader{$SInfo->{"MnglName"}})
        {
            $SInfo->{"Header"} = chooseHeader($SInfo->{"MnglName"}, $SInfo->{"Source"});
            delete($SInfo->{"Line"});
        }
        elsif(not $SInfo->{"Class"}
        and defined $SymbolToHeader{$SInfo->{"ShortName"}})
        {
            $SInfo->{"Header"} = chooseHeader($SInfo->{"ShortName"}, $SInfo->{"Source"});
            delete($SInfo->{"Line"});
        }
    }
    
    if($SInfo->{"Alias"})
    {
        if(defined $SymbolToHeader{$SInfo->{"Alias"}}) {
            $SInfo->{"Header"} = chooseHeader($SInfo->{"Alias"}, $SInfo->{"Source"});
        }
    }
}

sub chooseHeader($$)
{
    my ($Symbol, $Source) = @_;
    
    my @Headers = sort keys(%{$SymbolToHeader{$Symbol}});
    
    if($#Headers==0) {
        return $Headers[0];
    }
    
    @Headers = sort {length($a)<=>length($b)} sort {lc($a) cmp lc($b)} @Headers;
    
    $Source=~s/\.\w+\Z//g;
    
    foreach my $Header (@Headers)
    {
        if($Header=~/\A\Q$Source\E(|\.[\w\+]+)\Z/i) {
            return $Header;
        }
    }
    
    my $SPrefix = undef;
    
    if(length($Source)>3) {
        $SPrefix = substr($Source, 0, 3);
    }
    
    if(defined $SPrefix)
    {
        foreach my $Header (@Headers)
        {
            if($Header=~/\A\Q$SPrefix\E/i) {
                return $Header;
            }
        }
    }
    
    return $Headers[0];
}

sub getTypeIdByName($$)
{
    my ($Type, $Name) = @_;
    return $TName_Tid{$Type}{formatName($Name, "T")};
}

sub getFirst($)
{
    my $Tid = $_[0];
    if(not $Tid) {
        return $Tid;
    }
    
    if(defined $DeletedAnon{$Tid}) {
        $Tid = $DeletedAnon{$Tid};
    }
    
    if(defined $TypeSpec{$Tid}) {
        $Tid = $TypeSpec{$Tid};
    }
    
    if(my $Name = $TypeInfo{$Tid}{"Name"})
    {
        my $Type = $TypeInfo{$Tid}{"Type"};
        
        my $FTid = undef;
        
        if($FTid = $TName_Tid{$Type}{$Name}) {
            return "$FTid";
        }
        
        if($Name=~s/\Astruct //)
        { # search for class or derived types (const, *, etc.)
            foreach my $Type ("Class", "Const", "Ref", "RvalueRef", "Pointer")
            {
                if($FTid = $TName_Tid{$Type}{$Name})
                {
                    if($FTid ne $Tid)
                    {
                        $MergedTypes{$Tid} = 1;
                    }
                    return "$FTid";
                }
            }
            
            $Name = "struct ".$Name;
        }
        
        if(not $FTid) {
            $FTid = $TName_Tid{$Type}{$Name};
        }
        
        if($FTid) {
            return "$FTid";
        }
        printMsg("ERROR", "internal error (missed type id $Tid)");
    }
    
    return $Tid;
}

sub searchTypeID($)
{
    my $Name = $_[0];
    
    my %Pr = map {$_=>1} (
        "Struct",
        "Union",
        "Enum"
    );
    
    foreach my $Type ("Class", "Struct", "Union", "Enum", "Typedef", "Const",
    "Volatile", "Ref", "RvalueRef", "Pointer", "FuncPtr", "MethodPtr", "FieldPtr")
    {
        my $Tid = $TName_Tid{$Type}{$Name};
        
        if(not $Tid)
        {
            if(defined $Pr{$Type})
            {
                my $NN = lc($Type)." ".$Name;
                if(defined $TName_Tid{$Type}{$NN}) {
                    $Tid = $TName_Tid{$Type}{$NN};
                }
            }
        }
        if($Tid) {
            return $Tid;
        }
    }
    return undef;
}

sub removeUnused()
{ # remove unused data types from the ABI dump
    %HeadersInfo = ();
    %SourcesInfo = ();
    
    my (%SelectedHeaders, %SelectedSources) = ();
    
    foreach my $ID (sort {$a<=>$b} keys(%SymbolInfo))
    {
        if($SelectedSymbols{$ID}==2)
        { # data, inline, pure
            next;
        }
        
        registerSymbolUsage($ID);
        
        if(my $H = $SymbolInfo{$ID}{"Header"}) {
            $SelectedHeaders{$H} = 1;
        }
        if(my $S = $SymbolInfo{$ID}{"Source"}) {
            $SelectedSources{$S} = 1;
        }
    }
    
    foreach my $ID (sort {$a<=>$b} keys(%SymbolInfo))
    {
        if($SelectedSymbols{$ID}==2)
        { # data, inline, pure
            my $Save = 0;
            if(my $Class = getFirst($SymbolInfo{$ID}{"Class"}))
            {
                if(defined $UsedType{$Class}) {
                    $Save = 1;
                }
                else
                {
                    if(defined $ClassChild{$Class})
                    {
                        foreach (keys(%{$ClassChild{$Class}}))
                        {
                            if(defined $UsedType{getFirst($_)})
                            {
                                $Save = 1;
                                last;
                            }
                        }
                    }
                }
            }
            if(my $Header = $SymbolInfo{$ID}{"Header"})
            {
                if(defined $SelectedHeaders{$Header}) {
                    $Save = 1;
                }
            }
            if(my $Source = $SymbolInfo{$ID}{"Source"})
            {
                if(defined $SelectedSources{$Source}) {
                    $Save = 1;
                }
            }
            if($Save) {
                registerSymbolUsage($ID);
            }
            else {
                delete($SymbolInfo{$ID});
            }
        }
    }
    
    if(defined $AllTypes)
    {
        # register all data types (except anon structs and unions)
        foreach my $Tid (keys(%TypeInfo))
        {
            if(defined $LocalType{$Tid})
            { # except local code
                next;
            }
            if($TypeInfo{$Tid}{"Type"} eq "Enum"
            or index($TypeInfo{$Tid}{"Name"}, "anon-")!=0) {
                registerTypeUsage($Tid);
            }
        }
        
        # remove unused anons (except enums)
        foreach my $Tid (keys(%TypeInfo))
        {
            if(not $UsedType{$Tid})
            {
                if($TypeInfo{$Tid}{"Type"} ne "Enum")
                {
                    if(index($TypeInfo{$Tid}{"Name"}, "anon-")==0) {
                        delete($TypeInfo{$Tid});
                    }
                }
            }
        }
        
        # remove duplicates
        foreach my $Tid (keys(%TypeInfo))
        {
            my $Name = $TypeInfo{$Tid}{"Name"};
            my $Type = $TypeInfo{$Tid}{"Type"};
            
            if($TName_Tid{$Type}{$Name} ne $Tid) {
                delete($TypeInfo{$Tid});
            }
        }
    }
    else
    {
        foreach my $Tid (keys(%TypeInfo))
        { # remove unused types
            if(not $UsedType{$Tid}) {
                delete($TypeInfo{$Tid});
            }
        }
    }
    
    foreach my $Tid (keys(%MergedTypes)) {
        delete($TypeInfo{$Tid});
    }
    
    foreach my $Tid (keys(%LocalType))
    {
        if(not $UsedType{$Tid}) {
            delete($TypeInfo{$Tid});
        }
    }
    
    # clean memory
    %MergedTypes = ();
    %LocalType = ();
    
    # completeness
    foreach my $Tid (sort keys(%TypeInfo)) {
        checkCompleteness($TypeInfo{$Tid});
    }
    
    foreach my $Sid (sort keys(%SymbolInfo)) {
        checkCompleteness($SymbolInfo{$Sid});
    }
    
    # clean memory
    %UsedType = ();
}

sub simpleName($)
{
    my $N = $_[0];
    
    $N=~s/\A(struct|class|union|enum) //; # struct, class, union, enum
    
    if(index($N, "std::basic_string")!=-1)
    {
        $N=~s/std::basic_string<char, std::char_traits<char>, std::allocator<char> >/std::string /g;
        $N=~s/std::basic_string<char, std::char_traits<char> >/std::string /g;
        $N=~s/std::basic_string<char>/std::string /g;
        
        $N=~s/std::basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t> >/std::wstring /g;
    }
    
    if(index($N, "std::basic_ostream")!=-1) {
        $N=~s/std::basic_ostream<char, std::char_traits<char> >/std::ostream /g;
    }
    
    return formatName($N, "T");
}

sub registerSymbolUsage($)
{
    my $InfoId = $_[0];
    
    my %FuncInfo = %{$SymbolInfo{$InfoId}};
    
    if(my $S = $FuncInfo{"Source"}) {
        $SourcesInfo{$S} = 1;
    }
    if(my $H = $FuncInfo{"Header"}) {
        $HeadersInfo{$H} = 1;
    }
    if(my $RTid = getFirst($FuncInfo{"Return"}))
    {
        registerTypeUsage($RTid);
        $SymbolInfo{$InfoId}{"Return"} = $RTid;
    }
    if(my $FCid = getFirst($FuncInfo{"Class"}))
    {
        registerTypeUsage($FCid);
        $SymbolInfo{$InfoId}{"Class"} = $FCid;
        
        if(my $ThisId = getTypeIdByName("Const", $TypeInfo{$FCid}{"Name"}."*const"))
        { # register "this" pointer
            registerTypeUsage($ThisId);
        }
        if(my $ThisId_C = getTypeIdByName("Const", $TypeInfo{$FCid}{"Name"}." const*const"))
        { # register "this" pointer (const method)
            registerTypeUsage($ThisId_C);
        }
    }
    foreach my $PPos (keys(%{$FuncInfo{"Param"}}))
    {
        if(my $PTid = getFirst($FuncInfo{"Param"}{$PPos}{"type"}))
        {
            registerTypeUsage($PTid);
            $SymbolInfo{$InfoId}{"Param"}{$PPos}{"type"} = $PTid;
        }
    }
    foreach my $TPos (keys(%{$FuncInfo{"TParam"}}))
    {
        if(my $TTid = $FuncInfo{"TParam"}{$TPos}{"type"})
        {
            if($TTid = getFirst($TTid))
            {
                registerTypeUsage($TTid);
                $SymbolInfo{$InfoId}{"TParam"}{$TPos}{"type"} = $TTid;
                delete($SymbolInfo{$InfoId}{"TParam"}{$TPos}{"name"});
            }
        }
        elsif(my $TPName = $FuncInfo{"TParam"}{$TPos}{"name"})
        {
            if(my $TTid = searchTypeID($TPName))
            {
                if(my $FTTid = getFirst($TTid))
                {
                    registerTypeUsage($FTTid);
                    $SymbolInfo{$InfoId}{"TParam"}{$TPos}{"type"} = $TTid;
                    delete($SymbolInfo{$InfoId}{"TParam"}{$TPos}{"name"});
                }
            }
        }
    }
}

sub registerTypeUsage($)
{
    my $TypeId = $_[0];
    if(not $TypeId) {
        return 0;
    }
    if($UsedType{$TypeId})
    { # already registered
        return 1;
    }
    my %TInfo = %{$TypeInfo{$TypeId}};
    
    if(my $S = $TInfo{"Source"}) {
        $SourcesInfo{$S} = 1;
    }
    if(my $H = $TInfo{"Header"}) {
        $HeadersInfo{$H} = 1;
    }
    
    if($TInfo{"Type"})
    {
        if(my $NS = $TInfo{"NameSpace"})
        {
            if(my $NSTid = searchTypeID($NS))
            {
                if(my $FNSTid = getFirst($NSTid)) {
                    registerTypeUsage($FNSTid);
                }
            }
        }
        
        if($TInfo{"Type"}=~/\A(Struct|Union|Class|FuncPtr|Func|MethodPtr|FieldPtr|Enum)\Z/)
        {
            $UsedType{$TypeId} = 1;
            if($TInfo{"Type"}=~/\A(Struct|Class)\Z/)
            {
                foreach my $BaseId (keys(%{$TInfo{"Base"}}))
                { # register base classes
                    if(my $FBaseId = getFirst($BaseId))
                    {
                        registerTypeUsage($FBaseId);
                        if($FBaseId ne $BaseId)
                        {
                            %{$TypeInfo{$TypeId}{"Base"}{$FBaseId}} = %{$TypeInfo{$TypeId}{"Base"}{$BaseId}};
                            delete($TypeInfo{$TypeId}{"Base"}{$BaseId});
                        }
                    }
                }
            }
            if($TInfo{"Type"}=~/\A(Struct|Class|Union)\Z/)
            {
                foreach my $TPos (keys(%{$TInfo{"TParam"}}))
                {
                    if(my $TTid = $TInfo{"TParam"}{$TPos}{"type"})
                    {
                        if($TTid = getFirst($TTid))
                        {
                            registerTypeUsage($TTid);
                            $TypeInfo{$TypeId}{"TParam"}{$TPos}{"type"} = $TTid;
                            delete($TypeInfo{$TypeId}{"TParam"}{$TPos}{"name"});
                        }
                    }
                    elsif(my $TPName = $TInfo{"TParam"}{$TPos}{"name"})
                    {
                        if(my $TTid = searchTypeID($TPName))
                        {
                            if(my $TTid = getFirst($TTid))
                            {
                                registerTypeUsage($TTid);
                                $TypeInfo{$TypeId}{"TParam"}{$TPos}{"type"} = $TTid;
                                delete($TypeInfo{$TypeId}{"TParam"}{$TPos}{"name"});
                            }
                        }
                    }
                }
            }
            foreach my $Memb_Pos (keys(%{$TInfo{"Memb"}}))
            {
                if(my $MTid = getFirst($TInfo{"Memb"}{$Memb_Pos}{"type"}))
                {
                    registerTypeUsage($MTid);
                    $TypeInfo{$TypeId}{"Memb"}{$Memb_Pos}{"type"} = $MTid;
                }
            }
            if($TInfo{"Type"} eq "FuncPtr"
            or $TInfo{"Type"} eq "MethodPtr"
            or $TInfo{"Type"} eq "Func")
            {
                if(my $RTid = getFirst($TInfo{"Return"}))
                {
                    registerTypeUsage($RTid);
                    $TypeInfo{$TypeId}{"Return"} = $RTid;
                }
                foreach my $Memb_Pos (keys(%{$TInfo{"Param"}}))
                {
                    if(my $MTid = getFirst($TInfo{"Param"}{$Memb_Pos}{"type"}))
                    {
                        registerTypeUsage($MTid);
                        $TypeInfo{$TypeId}{"Param"}{$Memb_Pos}{"type"} = $MTid;
                    }
                }
            }
            if($TInfo{"Type"} eq "FieldPtr")
            {
                if(my $RTid = getFirst($TInfo{"Return"}))
                {
                    registerTypeUsage($RTid);
                    $TypeInfo{$TypeId}{"Return"} = $RTid;
                }
                if(my $CTid = getFirst($TInfo{"Class"}))
                {
                    registerTypeUsage($CTid);
                    $TypeInfo{$TypeId}{"Class"} = $CTid;
                }
            }
            if($TInfo{"Type"} eq "MethodPtr")
            {
                if(my $CTid = getFirst($TInfo{"Class"}))
                {
                    registerTypeUsage($CTid);
                    $TypeInfo{$TypeId}{"Class"} = $CTid;
                }
            }
            if($TInfo{"Type"} eq "Enum")
            {
                if(my $BTid = getFirst($TInfo{"BaseType"}))
                {
                    registerTypeUsage($BTid);
                    $TypeInfo{$TypeId}{"BaseType"} = $BTid;
                }
            }
            return 1;
        }
        elsif($TInfo{"Type"}=~/\A(Const|ConstVolatile|Volatile|Pointer|Ref|RvalueRef|Restrict|Array|Typedef)\Z/)
        {
            $UsedType{$TypeId} = 1;
            if(my $BTid = getFirst($TInfo{"BaseType"}))
            {
                registerTypeUsage($BTid);
                $TypeInfo{$TypeId}{"BaseType"} = $BTid;
            }
            return 1;
        }
        elsif($TInfo{"Type"}=~/\A(Intrinsic|Unspecified)\Z/)
        {
            $UsedType{$TypeId} = 1;
            return 1;
        }
    }
    return 0;
}

sub checkCompleteness($)
{
    my $Info = $_[0];
    
    # data types
    if(defined $Info->{"Memb"})
    {
        foreach my $Pos (sort keys(%{$Info->{"Memb"}}))
        {
            if(defined $Info->{"Memb"}{$Pos}{"type"}) {
                checkTypeInfo($Info->{"Memb"}{$Pos}{"type"});
            }
        }
    }
    if(defined $Info->{"Base"})
    {
        foreach my $Bid (sort keys(%{$Info->{"Base"}})) {
            checkTypeInfo($Bid);
        }
    }
    if(defined $Info->{"BaseType"}) {
        checkTypeInfo($Info->{"BaseType"});
    }
    if(defined $Info->{"TParam"})
    {
        foreach my $Pos (sort keys(%{$Info->{"TParam"}}))
        {
            my $TRef = $Info->{"TParam"}{$Pos};
            
            if(my $Tid = $TRef->{"type"}) {
                checkTypeInfo($Tid);
            }
            else
            {
                my $TName = $Info->{"TParam"}{$Pos}{"name"};
                if($TName=~/\A(true|false|\d.*)\Z/) {
                    next;
                }
                
                if(my $Tid = searchTypeID($TName)) {
                    checkTypeInfo($Tid);
                }
                else
                {
                    if(defined $Loud) {
                        printMsg("WARNING", "missed type $TName");
                    }
                }
            }
        }
    }
    
    # symbols
    if(defined $Info->{"Param"})
    {
        foreach my $Pos (sort keys(%{$Info->{"Param"}}))
        {
            if(defined $Info->{"Param"}{$Pos}{"type"}) {
                checkTypeInfo($Info->{"Param"}{$Pos}{"type"});
            }
        }
    }
    if(defined $Info->{"Return"}) {
        checkTypeInfo($Info->{"Return"});
    }
    if(defined $Info->{"Class"}) {
        checkTypeInfo($Info->{"Class"});
    }
}

sub checkTypeInfo($)
{
    my $Tid = $_[0];
    
    if(defined $CheckedType{$Tid}) {
        return;
    }
    $CheckedType{$Tid} = 1;
    
    if(defined $TypeInfo{$Tid})
    {
        if(not $TypeInfo{$Tid}{"Name"}) {
            printMsg("ERROR", "missed type name ($Tid)");
        }
        checkCompleteness($TypeInfo{$Tid});
    }
    else {
        printMsg("ERROR", "missed type id $Tid");
    }
}

sub initRegs()
{
    if($SYS_ARCH eq "x86")
    {
        %RegName = (
        # integer registers
        # 32 bits
            "0"=>"eax",
            "1"=>"ecx",
            "2"=>"edx",
            "3"=>"ebx",
            "4"=>"esp",
            "5"=>"ebp",
            "6"=>"esi",
            "7"=>"edi",
            "8"=>"eip",
            "9"=>"eflags",
            "10"=>"trapno",
        # FPU-control registers
        # 16 bits
            "37"=>"fctrl",
            "38"=>"fstat",
        # 32 bits
            "39"=>"mxcsr",
        # MMX registers
        # 64 bits
            "29"=>"mm0",
            "30"=>"mm1",
            "31"=>"mm2",
            "32"=>"mm3",
            "33"=>"mm4",
            "34"=>"mm5",
            "35"=>"mm6",
            "36"=>"mm7",
        # SSE registers
        # 128 bits
            "21"=>"xmm0",
            "22"=>"xmm1",
            "23"=>"xmm2",
            "24"=>"xmm3",
            "25"=>"xmm4",
            "26"=>"xmm5",
            "27"=>"xmm6",
            "28"=>"xmm7",
        # segment registers
        # 16 bits
            "40"=>"es",
            "41"=>"cs",
            "42"=>"ss",
            "43"=>"ds",
            "44"=>"fs",
            "45"=>"gs",
        # x87 registers
        # 80 bits
            "11"=>"st0",
            "12"=>"st1",
            "13"=>"st2",
            "14"=>"st3",
            "15"=>"st4",
            "16"=>"st5",
            "17"=>"st6",
            "18"=>"st7"
        );
    }
    elsif($SYS_ARCH eq "x86_64")
    {
        %RegName = (
        # integer registers
        # 64 bits
            "0"=>"rax",
            "1"=>"rdx",
            "2"=>"rcx",
            "3"=>"rbx",
            "4"=>"rsi",
            "5"=>"rdi",
            "6"=>"rbp",
            "7"=>"rsp",
            "8"=>"r8",
            "9"=>"r9",
            "10"=>"r10",
            "11"=>"r11",
            "12"=>"r12",
            "13"=>"r13",
            "14"=>"r14",
            "15"=>"r15",
            "16"=>"rip",
            "49"=>"rFLAGS",
        # MMX registers
        # 64 bits
            "41"=>"mm0",
            "42"=>"mm1",
            "43"=>"mm2",
            "44"=>"mm3",
            "45"=>"mm4",
            "46"=>"mm5",
            "47"=>"mm6",
            "48"=>"mm7",
        # SSE registers
        # 128 bits
            "17"=>"xmm0",
            "18"=>"xmm1",
            "19"=>"xmm2",
            "20"=>"xmm3",
            "21"=>"xmm4",
            "22"=>"xmm5",
            "23"=>"xmm6",
            "24"=>"xmm7",
            "25"=>"xmm8",
            "26"=>"xmm9",
            "27"=>"xmm10",
            "28"=>"xmm11",
            "29"=>"xmm12",
            "30"=>"xmm13",
            "31"=>"xmm14",
            "32"=>"xmm15",
        # control registers
        # 64 bits
            "62"=>"tr", 
            "63"=>"ldtr",
            "64"=>"mxcsr",
        # 16 bits
            "65"=>"fcw",
            "66"=>"fsw",
        # segment registers
        # 16 bits
            "50"=>"es",
            "51"=>"cs",
            "52"=>"ss",
            "53"=>"ds",
            "54"=>"fs",
            "55"=>"gs",
        # 64 bits
            "58"=>"fs.base",
            "59"=>"gs.base",
        # x87 registers
        # 80 bits
            "33"=>"st0",
            "34"=>"st1",
            "35"=>"st2",
            "36"=>"st3",
            "37"=>"st4",
            "38"=>"st5",
            "39"=>"st6",
            "40"=>"st7"
        );
    }
    elsif($SYS_ARCH eq "arm")
    {
        %RegName = (
        # integer registers
        # 32-bit
            "0"=>"r0",
            "1"=>"r1",
            "2"=>"r2",
            "3"=>"r3",
            "4"=>"r4",
            "5"=>"r5",
            "6"=>"r6",
            "7"=>"r7",
            "8"=>"r8",
            "9"=>"r9",
            "10"=>"r10",
            "11"=>"r11",
            "12"=>"r12",
            "13"=>"r13",
            "14"=>"r14",
            "15"=>"r15"
        );
    }
}

sub dumpSorting($)
{
    my $Hash = $_[0];
    return [] if(not $Hash);
    my @Keys = keys(%{$Hash});
    return [] if($#Keys<0);
    if($Keys[0]=~/\A\d+\Z/)
    { # numbers
        return [sort {$a<=>$b} @Keys];
    }
    else
    { # strings
        return [sort {$a cmp $b} @Keys];
    }
}

sub getDebugFile($$)
{
    my ($Obj, $Header) = @_;
    
    my $Str = `$EU_READELF_L --strings=.$Header \"$Obj\" 2>\"$TMP_DIR/error\"`;
    if($Str=~/(\s|\[)0\]\s*(.+)/) {
        return $2;
    }
    
    return undef;
}

sub findFiles(@)
{
    my ($Path, $Type) = @_;
    my $Cmd = "find \"$Path\"";
    
    if($Type) {
        $Cmd .= " -type ".$Type;
    }
    
    my @Res = split(/\n/, `$Cmd`);
    return @Res;
}

sub isHeader($)
{
    my $Path = $_[0];
    
    if($Path=~/\.($HEADER_EXT)\Z/i) {
        return 1;
    }
    
    if(index(getFilename($Path), ".")==-1 and -T $Path)
    { # C++
        return 1;
    }
    
    return 0;
}

sub detectPublicSymbols($)
{
    my $Path = $_[0];
    
    if(not -e $Path) {
        exitStatus("Access_Error", "can't access \'$Path\'");
    }
    
    my $Path_A = abs_path($Path);
    
    printMsg("INFO", "Detect public symbols");
    
    if($UseTU)
    {
        if(not checkCmd($GPP)) {
            exitStatus("Not_Found", "can't find \"$GPP\"");
        }
    }
    else
    {
        if(not checkCmd($CTAGS)) {
            exitStatus("Not_Found", "can't find \"$CTAGS\"");
        }
        
        if(my $CtagsVer = `$CTAGS --version 2>&1`)
        {
            if($CtagsVer!~/Universal/i)
            {
                printMsg("ERROR", "requires Universal Ctags to work properly");
                if($CtagsVer=~/Exuberant/i) {
                    $EXUBERANT_CTAGS = 1;
                }
            }
        }
    }
    
    $PublicSymbols_Detected = 1;
    
    my @Files = ();
    my @Headers = ();
    my @DefaultInc = ();
    
    if($PublicHeadersIsDir)
    { # directory
        @Files = findFiles($Path, "f");
        
        foreach my $File (@Files)
        {
            if(isHeader($File)) {
                push(@Headers, $File);
            }
        }
        
        push(@DefaultInc, $Path_A);
        
        if(-d $Path_A."/include") {
            push(@DefaultInc, $Path_A."/include");
        }
    }
    else
    { # list of headers
        @Headers = split(/\n/, readFile($Path));
    }
    
    if(not @Headers) {
        exitStatus("Error", "headers not found in \'$Path\'");
    }
    
    my $PublicHeader_F = $CacheHeaders."/PublicHeader.data";
    my $SymbolToHeader_F = $CacheHeaders."/SymbolToHeader.data";
    my $TypeToHeader_F = $CacheHeaders."/TypeToHeader.data";
    my $Path_F = $CacheHeaders."/PATH";
    
    if($CacheHeaders
    and -f $PublicHeader_F
    and -f $SymbolToHeader_F
    and -f $TypeToHeader_F
    and -f $Path_F)
    {
        if(readFile($Path_F) eq $Path_A)
        {
            %PublicHeader = %{eval(readFile($PublicHeader_F))};
            %SymbolToHeader = %{eval(readFile($SymbolToHeader_F))};
            %TypeToHeader = %{eval(readFile($TypeToHeader_F))};
            
            return;
        }
    }
    
    foreach my $File (@Headers)
    {
        $PublicHeader{getFilename($File)} = 1;
    }
    
    my $Is_C = ($OBJ_LANG eq "C");
    
    my @Langs = undef;
    
    if($EXUBERANT_CTAGS)
    {
        @Langs = ("C++");
        if($Is_C) {
            @Langs = ("C");
        }
    }
    else
    {
        @Langs = ("C++", "OldC++");
        if($Is_C) {
            @Langs = ("C", "OldC");
        }
    }
    
    @Headers = sort {length($b)<=>length($a)} sort {lc($b) cmp lc($a)} @Headers;
    
    foreach my $File (@Headers)
    {
        my $HName = getFilename($File);
        
        if($UseTU)
        {
            my $TmpDir = $TMP_DIR."/tu";
            if(not -d $TmpDir) {
                mkpath($TmpDir);
            }
            
            my $File_A = abs_path($File);
            
            my $IncDir = getDirname($File_A);
            my $IncDir_O = getDirname($IncDir);
            
            my $TmpInc = $TmpDir."/tmp-inc.h";
            my $TmpContent = "";
            if($IncludeDefines)
            {
                foreach my $D (split(/;/, $IncludeDefines)) {
                    $TmpContent = "#define $D\n";
                }
            }
            if($IncludePreamble)
            {
                foreach my $P (split(/;/, $IncludePreamble))
                {
                    if($P=~/\A\//) {
                        $TmpContent = "#include \"".$P."\"\n";
                    }
                    else {
                        $TmpContent = "#include <".$P.">\n";
                    }
                }
            }
            $TmpContent .= "#include \"$File_A\"\n";
            writeFile($TmpInc, $TmpContent);
            
            my $Cmd = $GPP." -w -fpermissive -fdump-translation-unit -fkeep-inline-functions -c \"$TmpInc\"";
            
            if(defined $IncludePaths)
            {
                foreach my $P (split(/;/, $IncludePaths))
                {
                    if($P!~/\A\//) {
                        $P = $Path_A."/".$P;
                    }
                    
                    $Cmd .= " -I\"".$P."\"";
                }
            }
            else
            { # automatic
                $Cmd .= " -I\"$IncDir\" -I\"$IncDir_O\"";
            }
            
            foreach my $P (@DefaultInc) {
                $Cmd .= " -I\"$P\"";
            }
            
            $Cmd .= " -o ./a.out >OUT 2>&1";
            
            chdir($TmpDir);
            system($Cmd);
            chdir($ORIG_DIR);
            
            my $TuDump = $TmpDir."/tmp-inc.h.001t.tu";
            my $Errors = $TmpDir."/OUT";
            
            if(not -e $TuDump)
            {
                printMsg("ERROR", "failed to list symbols in the header \'$HName\'");
                if($Debug) {
                    printMsg("ERROR", readFile($Errors));
                }
                next;
            }
            elsif($?)
            {
                printMsg("ERROR", "some errors occured when compiling header \'$HName\'");
                if($Debug) {
                    printMsg("ERROR", readFile($Errors));
                }
            }
            
            my (%Fdecl, %Tdecl, %Tname, %Ident, %NotDecl) = ();
            my $Content = readFile($TuDump);
            $Content=~s/\n[ ]+/ /g;
            
            my @Lines = split(/\n/, $Content);
            foreach my $N (0 .. $#Lines)
            {
                my $Line = $Lines[$N];
                if(index($Line, "function_decl")!=-1
                or index($Line, "var_decl")!=-1)
                {
                    if($Line=~/name: \@(\d+)/)
                    {
                        my $Id = $1;
                        
                        if($Line=~/srcp: ([^:]+)\:\d/)
                        {
                            if(defined $PublicHeader{$1}) {
                                $Fdecl{$Id} = $1;
                            }
                        }
                    }
                }
                elsif($Line=~/\@(\d+)\s+identifier_node\s+strg:\s+(\w+)/)
                {
                    $Ident{$1} = $2;
                }
                elsif($Is_C)
                {
                    if(index($Line, "type_decl")!=-1)
                    {
                        if($Line=~/\A\@(\d+)/)
                        {
                            my $Id = $1;
                            if($Line=~/name: \@(\d+)/)
                            {
                                my $NId = $1;
                                
                                if($Line=~/srcp: ([^:]+)\:\d/)
                                {
                                    if(defined $PublicHeader{$1})
                                    {
                                        $Tdecl{$Id} = $1;
                                        $Tname{$Id} = $NId;
                                    }
                                }
                            }
                        }
                    }
                    elsif(index($Line, "record_type")!=-1
                    or index($Line, "union_type")!=-1)
                    {
                        if($Line!~/ flds:/)
                        {
                            if($Line=~/name: \@(\d+)/)
                            {
                                $NotDecl{$1} = 1;
                            }
                        }
                    }
                    elsif(index($Line, "enumeral_type")!=-1)
                    {
                        if($Line!~/ csts:/)
                        {
                            if($Line=~/name: \@(\d+)/)
                            {
                                $NotDecl{$1} = 1;
                            }
                        }
                    }
                    elsif(index($Line, "integer_type")!=-1)
                    {
                        if($Line=~/name: \@(\d+)/)
                        {
                            $NotDecl{$1} = 1;
                        }
                    }
                }
            }
            
            foreach my $Id (keys(%Fdecl))
            {
                if(my $Name = $Ident{$Id}) {
                    $SymbolToHeader{$Name}{$Fdecl{$Id}} = 1;
                }
            }
            
            if($Is_C)
            {
                foreach my $Id (keys(%Tdecl))
                {
                    if(defined $NotDecl{$Id}) {
                        next;
                    }
                    
                    if(my $Name = $Ident{$Tname{$Id}}) {
                        $TypeToHeader{$Name} = $Tdecl{$Id};
                    }
                }
            }
            
            unlink($TuDump);
        }
        else
        { # using Ctags
            my $IgnoreTags = "";
            
            if(defined $IgnoreTagsPath) {
                $IgnoreTags .= " -I \@".$IgnoreTagsPath;
            }
            
            if(@CtagsDef)
            {
                foreach my $Def (@CtagsDef) {
                    $IgnoreTags .= " -D '".$Def."'";
                }
            }
            
            foreach my $Lang (@Langs)
            {
                my $List_S = `$CTAGS -x --$Lang-kinds=fpvxd --languages=+$Lang --language-force=$Lang $IgnoreTags \"$File\"`;
                foreach my $Line (split(/\n/, $List_S))
                {
                    if($Line=~/\A(\w+)\s+(\w+)/) {
                        $SymbolToHeader{$1}{$HName} = $2;
                    }
                    
                    if(index($Line, " macro ")!=-1)
                    {
                        if($Line=~/#define\s+(\w+)\s+(\w+)\Z/) {
                            $SymbolToHeader{$2}{$HName} = "prototype";
                        }
                    }
                    
                    if(not $Is_C)
                    {
                        if(index($Line, "operator ")==0)
                        {
                            if($Line=~/\A(operator) (\w.*?)\s+(prototype|function)/) {
                                $SymbolToHeader{$1." ".$2}{$HName} = $3;
                            }
                            elsif($Line=~/\A(operator) (\W.*?)\s+(prototype|function)/) {
                                $SymbolToHeader{$1.$2}{$HName} = $3;
                            }
                        }
                    }
                }
                
                if($Is_C)
                {
                    my $List_T = `$CTAGS -x --$Lang-kinds=gstu --languages=+$Lang --language-force=$Lang $IgnoreTags \"$File\"`;
                    foreach my $Line (split(/\n/, $List_T))
                    {
                        if($Line=~/\A(\w+)/)
                        {
                            my $N = $1;
                            
                            if($Line!~/\b$N\s+$N\b/) {
                                $TypeToHeader{$N} = $HName;
                            }
                        }
                    }
                }
            }
        }
    }
    
    # We can't fully rely on the output of Ctags because it may
    # miss some symbols intentionally (due to branches of code)
    # or occasionally (due to complex macros).
    if(not $UseTU)
    {
        foreach my $File (@Headers)
        {
            my $HName = getFilename($File);
            my $Content = readFile($File);
            
            $Content=~s&/\*.+?\*/&&sg;
            $Content=~s&(//|#define).*\n&\n&g;
            
            # Functions
            my @Func = ($Content=~/([a-zA-Z]\w+)\s*\(/g);
            foreach (@Func)
            {
                if(not defined $SymbolToHeader{$_} or not defined $SymbolToHeader{$_}{$HName}) {
                    $SymbolToHeader{$_}{$HName} = "prototype";
                }
            }
            
            # Data
            my @Data = ($Content=~/([a-zA-Z_]\w+)\s*;/gi);
            foreach (@Data)
            {
                if(not defined $SymbolToHeader{$_} or not defined $SymbolToHeader{$_}{$HName}) {
                    $SymbolToHeader{$_}{$HName} = "prototype";
                }
            }
            
            # Types
            if($Is_C)
            {
                my @Type1 = ($Content=~/}\s*([a-zA-Z]\w+)\s*;/g);
                my @Type2 = ($Content=~/([a-zA-Z]\w+)\s*{/g);
                foreach (@Type1, @Type2)
                {
                    if(not defined $TypeToHeader{$_} or not defined $TypeToHeader{$_}{$HName}) {
                        $TypeToHeader{$_}{$HName} = 1;
                    }
                }
            }
        }
    }
    
    if($CacheHeaders)
    {
        writeFile($PublicHeader_F, Dumper(\%PublicHeader));
        writeFile($SymbolToHeader_F, Dumper(\%SymbolToHeader));
        writeFile($TypeToHeader_F, Dumper(\%TypeToHeader));
        writeFile($Path_F, $Path_A);
    }
}

sub getDebugAltLink($)
{
    my $Obj = $_[0];
    
    my $AltDebugFile = getDebugFile($Obj, "gnu_debugaltlink");
    
    if(not $AltDebugFile) {
        return undef;
    }
    
    my $Dir = getDirname($Obj);
    
    my $AltObj_R = $AltDebugFile;
    if($Dir and $Dir ne ".") {
        $AltObj_R = $Dir."/".$AltObj_R;
    }
    
    if(-e $AltObj_R)
    {
        printMsg("INFO", "Set alternate debug-info file to \'$AltObj_R\' (use -alt option to change it)");
        return $AltObj_R;
    }
    
    printMsg("WARNING", "can't access \'$AltObj_R\'");
    return undef;
}

sub scenario()
{
    if($Help)
    {
        helpMsg();
        exit(0);
    }
    if($ShowVersion)
    {
        printMsg("INFO", "ABI Dumper $TOOL_VERSION EE");
        printMsg("INFO", "Copyright (C) 2025 Andrey Ponomarenko's ABI Laboratory");
        printMsg("INFO", "License: GNU LGPL 2.1 <http://www.gnu.org/licenses/>");
        printMsg("INFO", "This program is free software: you can redistribute it and/or modify it.\n");
        printMsg("INFO", "Written by Andrey Ponomarenko.");
        exit(0);
    }
    if($DumpVersion)
    {
        printMsg("INFO", $TOOL_VERSION);
        exit(0);
    }
    
    $Data::Dumper::Sortkeys = 1;
    
    if($SortDump) {
        $Data::Dumper::Sortkeys = \&dumpSorting;
    }
    
    if($SearchDirDebuginfo)
    {
        if(not -d $SearchDirDebuginfo) {
            exitStatus("Access_Error", "can't access directory \'$SearchDirDebuginfo\'");
        }
    }
    
    if($PublicHeadersPath)
    {
        if(not -e $PublicHeadersPath) {
            exitStatus("Access_Error", "can't access \'$PublicHeadersPath\'");
        }
        
        $PublicHeadersIsDir = (-d $PublicHeadersPath);
        
        foreach my $P (split(/;/, $IncludePaths))
        {
            if($PublicHeadersIsDir and $P!~/\A\//) {
                $P = $PublicHeadersPath."/".$P;
            }
            
            if(not -e $P) {
                exitStatus("Access_Error", "can't access \'$P\'");
            }
        }
    }
    
    if($SymbolsListPath)
    {
        if(not -f $SymbolsListPath) {
            exitStatus("Access_Error", "can't access file \'$SymbolsListPath\'");
        }
        foreach my $S (split(/\s*\n\s*/, readFile($SymbolsListPath))) {
            $SymbolsList{$S} = 1;
        }
    }
    
    if($VTDumperPath)
    {
        if(not -x $VTDumperPath) {
            exitStatus("Access_Error", "can't access \'$VTDumperPath\'");
        }
        
        $VTABLE_DUMPER = $VTDumperPath;
    }
    
    if(defined $Compare)
    {
        my $P1 = $ARGV[0];
        my $P2 = $ARGV[1];
        
        if(not $P1) {
            exitStatus("Error", "arguments are not specified");
        }
        elsif(not -e $P1) {
            exitStatus("Access_Error", "can't access \'$P1\'");
        }
        
        if(not $P2) {
            exitStatus("Error", "second argument is not specified");
        }
        elsif(not -e $P2) {
            exitStatus("Access_Error", "can't access \'$P2\'");
        }
        
        my %ABI = ();
        
        $ABI{1} = eval(readFile($P1));
        $ABI{2} = eval(readFile($P2));
        
        my %SymInfo = ();
        
        foreach (1, 2)
        {
            foreach my $ID (keys(%{$ABI{$_}->{"SymbolInfo"}}))
            {
                my $Info = $ABI{$_}->{"SymbolInfo"}{$ID};
                
                if(my $MnglName = $Info->{"MnglName"}) {
                    $SymInfo{$_}{$MnglName} = $Info;
                }
                elsif(my $ShortName = $Info->{"ShortName"}) {
                    $SymInfo{$_}{$ShortName} = $Info;
                }
            }
        }
        
        foreach my $Symbol (sort keys(%{$SymInfo{1}}))
        {
            if(not defined $SymInfo{2}{$Symbol}) {
                printMsg("INFO", "Removed $Symbol");
            }
        }
        
        foreach my $Symbol (sort keys(%{$SymInfo{2}}))
        {
            if(not defined $SymInfo{1}{$Symbol}) {
                printMsg("INFO", "Added $Symbol");
            }
        }
        
        exit(0);
    }
    
    if($TargetVersion eq "") {
        printMsg("WARNING", "module version is not specified (-lver NUM)");
    }
    
    if($FullDump)
    {
        $AllTypes = 1;
        $AllSymbols = 1;
    }
    
    if(not $OutputDump) {
        $OutputDump = "./ABI.dump";
    }
    
    if(not @ARGV) {
        exitStatus("Error", "object path is not specified");
    }
    
    foreach my $Obj (@ARGV)
    {
        if(not -e $Obj) {
            exitStatus("Access_Error", "can't access \'$Obj\'");
        }
    }
    
    if($AltDebugInfoOpt)
    {
        if(not -e $AltDebugInfoOpt) {
            exitStatus("Access_Error", "can't access \'$AltDebugInfoOpt\'");
        }
        $AltDebugInfo = $AltDebugInfoOpt;
        readAltInfo($AltDebugInfoOpt);
    }
    
    if($ExtraInfo)
    {
        mkpath($ExtraInfo);
        $ExtraInfo = abs_path($ExtraInfo);
    }
    
    initABI();
    
    my $Res = 0;
    
    foreach my $Obj (@ARGV)
    {
        if($Obj=~/\.a\Z/) {
            exitStatus("Error", "analysis of static libraries is not supported, please dump ABIs of individual objects in the archive or compile a shared library");
        }
        
        if(not $TargetName)
        {
            $TargetName = getFilename(realpath($Obj));
            $TargetName=~s/\.debug\Z//; # nouveau.ko.debug
            
            if(index($TargetName, "libstdc++")==0
            or index($TargetName, "libc++")==0) {
                $STDCXX_TARGET = 1;
            }
        }
        
        readSymbols($Obj);
        
        if(not defined $PublicSymbols_Detected)
        {
            if(defined $PublicHeadersPath) {
                detectPublicSymbols($PublicHeadersPath);
            }
        }
        
        $Res += readDWARFInfo($Obj);
        
        %DWARF_Info = ();
        
        readVtables($Obj);
    }
    
    if(not defined $Library_Symbol{$TargetName}) {
        exitStatus("No_Exported", "can't find exported symbols in object(s), please add a shared object on command line");
    }
    
    if(not $Res) {
        exitStatus("No_DWARF", "can't find debug info in object(s)");
    }

    if(defined $ExtraDump)
    { # add v-table symbols
        add_VtableSymbols();
    }

    %VTable_Symbol = ();
    %VTable_Class = ();

    %VirtualTable = ();
    
    completeABI();
    selectSymbols();
    removeUnused();
    
    if(defined $PublicHeadersPath)
    {
        foreach my $Tid (sort {$a<=>$b} keys(%TypeInfo))
        {
            if(not $TypeInfo{$Tid}{"Header"}
            or not defined $PublicHeader{$TypeInfo{$Tid}{"Header"}})
            {
                if($TypeInfo{$Tid}{"Type"}=~/Struct|Union|Enum|Typedef/)
                {
                    my $TName = $TypeInfo{$Tid}{"Name"};
                    $TName=~s/\A(struct|class|union|enum) //g;
                    
                    if(defined $TypeToHeader{$TName}) {
                        $TypeInfo{$Tid}{"Header"} = $TypeToHeader{$TName};
                    }
                    #elsif(index($TName, "::")!=-1)
                    #{
                    #    if($TName=~/::(.+?)\Z/)
                    #    {
                    #        if(defined $TypeToHeader{$1})
                    #        {
                    #            $TypeInfo{$Tid}{"Header"} = $TypeToHeader{$1};
                    #        }
                    #    }
                    #}
                }
            }
            
            if(not selectPublicType($Tid)) {
                $TypeInfo{$Tid}{"PrivateABI"} = 1;
            }
        }
    }
    
    if(defined $PublicHeadersPath)
    {
        foreach my $H (keys(%HeadersInfo))
        {
            if(not defined $PublicHeader{getFilename($H)}) {
                delete($HeadersInfo{$H});
            }
        }
    }
    
    # free memory
    %Mangled_ID = ();
    %Checked_Spec = ();
    %SelectedSymbols = ();
    %Cache = ();
    
    %ClassChild = ();
    %TypeSpec = ();
    
    %SourceFile = ();
    %SourceFile_Alt = ();
    %DebugLoc = ();
    %TName_Tid = ();
    %TName_Tids = ();
    %SymbolTable = ();

    %SymbolAttribute = ();

    %NameSpace = ();
    
    %DeletedAnon = ();
    %CheckedType = ();
    %DuplBaseType = ();
    
    %KSymTab = ();
    %TypeToHeader = ();
    %PublicHeader = ();
    
    createABIFile();
    
    exit(0);
}

scenario();
