
# Allow the version to be provided as a parameter
param ( [string]$VERSION )
if (-not $VERSION) { $VERSION = "1.6.1" }

$STAGE="dev"
#$STAGE="release"
if ( ${ENV:STAGE} ) { $STAGE = ${ENV:STAGE} }

$BASE_DL="https://dist.apache.org/repos/dist/$STAGE/logging/log4cxx"
if ( ${ENV:BASE_DL} ) { $BASE_DL = ${ENV:BASE_DL} }

$ARCHIVE="apache-log4cxx-$VERSION"
if ( ${ENV:ARCHIVE} ) { $ARCHIVE = ${ENV:ARCHIVE} }

$TEST_DIRECTORY="${ENV:TEMP}/log4cxx-$VERSION"
if ( ${ENV:TEST_DIRECTORY} ) { $TEST_DIRECTORY = "${ENV:TEST_DIRECTORY}" }

try
{
  gpg --version | Out-Null
}
catch
{
  Write-Error "The gpg program directory must be included the PATH environment variable" -ErrorAction Stop
}

if (-not (Test-Path -Path "$TEST_DIRECTORY" -PathType Container))
{
  New-Item -ItemType Directory -Path "$TEST_DIRECTORY" -ErrorAction Stop
}
Set-Location -Path "$TEST_DIRECTORY"

$FULL_DL="$BASE_DL/$VERSION/$ARCHIVE"
$ARCHIVE_TYPES = @("tar.gz", "zip")
foreach ($ARCHIVE_TYPE in $ARCHIVE_TYPES)
{
  if (Test-Path "$ARCHIVE.$ARCHIVE_TYPE") { Remove-Item "$ARCHIVE.$ARCHIVE_TYPE" }
  Invoke-WebRequest -Uri "$FULL_DL.$ARCHIVE_TYPE" -OutFile "$ARCHIVE.$ARCHIVE_TYPE" -ErrorAction Stop
  $EXTS = @("asc", "sha512", "sha256")
  foreach ($EXT in $EXTS)
  {
    if (Test-Path "$ARCHIVE.$ARCHIVE_TYPE.$EXT") { Remove-Item "$ARCHIVE.$ARCHIVE_TYPE.$EXT" }
    Invoke-WebRequest -Uri "$FULL_DL.$ARCHIVE_TYPE.$EXT" -OutFile "$ARCHIVE.$ARCHIVE_TYPE.$EXT" -ErrorAction Stop
  }
  $SUMS = @("sha512", "sha256")
  foreach ($SUM in $SUMS)
  {
    Write-Output "Validating $ARCHIVE.$ARCHIVE_TYPE $SUM checksum..."
    $Line = @(Get-Content -Path "$ARCHIVE.$ARCHIVE_TYPE.$SUM")[0]
    $Fields = $Line -split '\s+'
    $Hash = $Fields[0].Trim().ToUpper()
    $ComputedHash = (Get-FileHash -Algorithm $SUM -Path "$ARCHIVE.$ARCHIVE_TYPE").Hash.ToUpper()
    if ($Hash -ne $ComputedHash)
    {
      Write-Error "Read from $ARCHIVE.$ARCHIVE_TYPE.${SUM}: $Hash" -ErrorAction Continue
      Write-Error "Computed: $ComputedHash"  -ErrorAction Continue
      Write-Error "${File}: Not Passed" -ErrorAction Stop
    }
  }
  Write-Output "Validating $ARCHIVE.$ARCHIVE_TYPE signature..."
  gpg --verify "$ARCHIVE.$ARCHIVE_TYPE.asc"
  if (!$? ) { exit 1 }
}

if (Test-Path "$ARCHIVE") { Remove-Item -Recurse "$ARCHIVE" }
if (Test-Path test-build) { Remove-Item -Recurse test-build }
Write-Output "Extracting files..."
Expand-Archive -Path "$ARCHIVE.zip" -DestinationPath . -ErrorAction Stop

# Check tools are on the PATH
try
{
  cmake --version | Out-Null
}
catch
{
  Write-Error "The cmake program directory must be included the PATH environment variable" -ErrorAction Stop
}

${LOG4CXX_TEST_PROGRAM_PATH}="C:/msys64/usr/bin"
if ( ${ENV:LOG4CXX_TEST_PROGRAM_PATH} ) { $LOG4CXX_TEST_PROGRAM_PATH = ${ENV:LOG4CXX_TEST_PROGRAM_PATH} }
cmake -S $ARCHIVE -B test-build "-DLOG4CXX_TEST_PROGRAM_PATH=$LOG4CXX_TEST_PROGRAM_PATH"
if ( ! $? ) { exit 1 }

cmake --build test-build --config Release
if ( ! $? ) { exit 1 }

Set-Location -Path test-build
ctest -C Release --output-on-failure

