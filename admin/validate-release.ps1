
# Allow the version to be provided as a parameter
param ( [string]$VERSION )
if (-not $VERSION) { $VERSION = "1.8.1" }

$STAGE="dev"
#$STAGE="release"
if ( ${ENV:STAGE} ) { $STAGE = ${ENV:STAGE} }
$CheckProvenance=( $STAGE -eq "dev" )

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
  New-Item -ItemType Directory -Path "$TEST_DIRECTORY" -ErrorAction Stop | Out-Null
}
pushd "$TEST_DIRECTORY"

if ( $CheckProvenance )
{
  try
  {
    gh --version | Out-Null
  }
  catch
  {
    Write-Output "GitHub CLI program (gh) is not available - provenance checks will be skipped"
    $CheckProvenance=$false
  }
}
if ( $CheckProvenance )
{
  $WORKFLOW="package_code"
  Write-Output "Downloading GitHub $WORKFLOW artifacts ..."
  if (Test-Path "release_files") { Remove-Item "release_files" -Recurse -Force }
  # Get the latest Run ID
  $RUN_ID = (gh run list --repo apache/logging-log4cxx --workflow="$WORKFLOW.yml" --limit 1 --json databaseId --jq '.[0].databaseId')
  if ( !$? ) { Write-Error "Failed to find a Github $WORKFLOW run id" -ErrorAction Stop }

  # Download the GitHub artifacts
  gh run download --repo apache/logging-log4cxx "$RUN_ID"
  if ( !$? -or (-not (Test-Path "release_files")) )
  { Write-Error "Failed to download Github $WORKFLOW run $RUN_ID artifacts"  -ErrorAction Stop }
  if (-not (Test-Path "release_files\$ARCHIVE.tar.gz.sha512") )
  {
    Write-Error  "$ARCHIVE.tar.gz.sha512 not found in GitHub $WORKFLOW run $RUN_ID artifacts" -ErrorAction Stop
  }
}

# Create a temporary gpg home directory, so only the downloaded KEYS are used to verify the signature.
$PREVIOUS_GPG_HOME="${ENV:GNUPGHOME}"
$GPG_HOME="$TEST_DIRECTORY/.gpg"
$LOGGING_KEYS="$GPG_HOME/KEYS"
${ENV:GNUPGHOME}="$GPG_HOME"
trap { ${ENV:GNUPGHOME}="$PREVIOUS_GPG_HOME" }
if (-not (Test-Path -Path "$GPG_HOME" -PathType Container))
{
  New-Item -ItemType Directory -Path "$GPG_HOME" -ErrorAction Stop | Out-Null
  Invoke-WebRequest https://downloads.apache.org/logging/KEYS -OutFile $LOGGING_KEYS -ErrorAction Stop
  gpg --batch --quiet --import $LOGGING_KEYS
  if (!$? ) { exit 1 }
}

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
  gpg --batch --verify "$ARCHIVE.$ARCHIVE_TYPE.asc" "$ARCHIVE.$ARCHIVE_TYPE"
  if (!$? ) { exit 1 }

  if ( Test-Path -Path "release_files\$ARCHIVE.$ARCHIVE_TYPE.sha512" )
  {
    Write-Output "Checking provenance"
    if (@(Get-Content -Path "$ARCHIVE.$ARCHIVE_TYPE.sha512")[0] -eq @(Get-Content -Path "release_files\$ARCHIVE.$ARCHIVE_TYPE.sha512")[0])
    {
       Write-Output "$ARCHIVE.$ARCHIVE_TYPE is from a GitHub workflow"
    }
    else
    {
      Write-Error "$ARCHIVE.$ARCHIVE_TYPE is not from a GitHub workflow" -ErrorAction Stop
    }
  }
}
${ENV:GNUPGHOME}="$PREVIOUS_GPG_HOME"

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

