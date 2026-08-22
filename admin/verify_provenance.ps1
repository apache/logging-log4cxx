
# Allow the version to be provided as a parameter
param ( [string]$VERSION )
if (-not $VERSION) { $VERSION = "1.8.1" }

try
{
  gh --version | Out-Null
}
catch
{
  Write-Error "The gh program directory must be included the PATH environment variable" -ErrorAction Stop
}

$ARCHIVE="apache-log4cxx-$VERSION"
if ( ${ENV:ARCHIVE} ) { $ARCHIVE = ${ENV:ARCHIVE} }

$TEST_DIRECTORY="${ENV:TEMP}/log4cxx-$VERSION"
if ( ${ENV:TEST_DIRECTORY} ) { $TEST_DIRECTORY = "${ENV:TEST_DIRECTORY}" }
foreach ($TYPE in @("tar.gz", "zip"))
{
  if (-not (Test-Path -Path "$TEST_DIRECTORY/$ARCHIVE.$TYPE.sha512"))
  { Write-Error "$ARCHIVE.$TYPE.sha512 not found in $TEST_DIRECTORY"  -ErrorAction Stop }
}

$WORKFLOW="package_code"

# Get the latest Run ID
$RUN_ID = (gh run list --workflow="$WORKFLOW.yml" --limit 1 --json databaseId --jq '.[0].databaseId')
if ( !$? ) { Write-Error "Failed to find a $WORKFLOW run id" -ErrorAction Stop }

# Download the artifacts
Write-Output "Downloading $WORKFLOW run $RUN_ID artifacts into '$TEST_DIRECTORY' ..."
gh run download "$RUN_ID" --dir "$TEST_DIRECTORY"
if ( $? ) { Write-Error "Failed to download $WORKFLOW artifacts"  -ErrorAction Stop }

# Compare hash codes
Write-Output "Comparing archive checksums"
Set-Location -Path "$TEST_DIRECTORY"
foreach ($TYPE in @("tar.gz", "zip"))
{
  if (-not (Test-Path -Path "release_files\$ARCHIVE.$TYPE.sha512")) { Write-Error "release_files\$ARCHIVE.$TYPE.sha512: not found" -ErrorAction Stop }
  if (@(Get-Content -Path "$ARCHIVE.$TYPE.sha512")[0] -eq @(Get-Content -Path "release_files\$ARCHIVE.$TYPE.sha512")[0])
  {
     Write-Output "$ARCHIVE.$TYPE.sha512: OK"
  }
  else
  {
    Write-Error "$ARCHIVE.$TYPE.sha512 is different" -ErrorAction Stop
  }
}
