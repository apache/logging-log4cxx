#!/bin/bash

set -e

VERSION=$1
if [ -z "$VERSION" ] ; then
  VERSION=1.8.1
fi

if [ -z "$STAGE" ] ; then
  STAGE=dev # Alternatively release
fi
CheckProvenance=$(( $STAGE == "dev" ? 1 : 0 ))

if [ -z "$BASE_DL" ] ; then
  BASE_DL=https://dist.apache.org/repos/dist/$STAGE/logging/log4cxx
fi
if [ -z "$ARCHIVE" ] ; then
  ARCHIVE=apache-log4cxx-$VERSION
fi
if [ -z "$TEST_DIRECTORY" ] ; then
  TEST_DIRECTORY=/tmp/log4cxx-$VERSION
fi

test -d "$TEST_DIRECTORY" || mkdir "$TEST_DIRECTORY"
cd "$TEST_DIRECTORY"

if $CheckProvenance ; then
  if gh --version >> /dev/null ; then
    WORKFLOW="package_code"
    echo "Downloading $WORKFLOW artifacts ..."
    # Get the latest Run ID
    RUN_ID=$(gh run list --repo apache/logging-log4cxx --workflow="$WORKFLOW.yml" --limit 1 --json databaseId --jq '.[0].databaseId')
    if [ $? -ne 0 ]; then
      echo "Failed to find a GitHub $WORKFLOW run id"
      exit 1
    fi
    # Download the artifacts
    test -d release_files && rm -rf release_files
    gh run download --repo apache/logging-log4cxx "$RUN_ID"
    if [ $? -ne 0 ] || [ ! -d release_files ]; then
      echo "Failed to download GitHub $WORKFLOW run $RUN_ID artifacts"
      exit 1
    fi
    if [ ! -f "release_files/$ARCHIVE.tar.gz.sha512" ] ; then
      echo "$ARCHIVE.tar.gz.sha512 not found in GitHub $WORKFLOW run $RUN_ID artifacts"
      exit 1
    fi
  else
    echo "GitHub CLI program (gh) is not available - provenance checks will be skipped"
  fi
fi

FULL_DL="$BASE_DL/$VERSION/$ARCHIVE"
for ARCHIVE_TYPE in "tar.gz" "zip" ; do
  test -f "$ARCHIVE.$ARCHIVE_TYPE" && rm "$ARCHIVE.$ARCHIVE_TYPE"
  wget "$FULL_DL.$ARCHIVE_TYPE" || exit $?
  for EXT in "asc" "sha512" "sha256"; do
    test -f "$ARCHIVE.$ARCHIVE_TYPE.$EXT" && rm "$ARCHIVE.$ARCHIVE_TYPE.$EXT"
    wget "$FULL_DL.$ARCHIVE_TYPE.$EXT" || exit $?
  done
  for SUM in "sha512" "sha256"; do
    echo "Validating $SUM checksum..."
    "${SUM}sum" --check  "$ARCHIVE.$ARCHIVE_TYPE.$SUM" || exit $?
  done
  echo "Validating signature..."
  gpg --verify "$ARCHIVE.$ARCHIVE_TYPE.asc" || exit $?

  if [ -f release_files/$ARCHIVE.$ARCHIVE_TYPE.sha512 ] ; then
    echo "Checking provenance ..."
    if diff {,release_files/}$ARCHIVE.$ARCHIVE_TYPE.sha512 ; then
      echo "$ARCHIVE.$ARCHIVE_TYPE is from a GitHub workflow"
    else
      echo "$ARCHIVE.$ARCHIVE_TYPE is not from a GitHub workflow"
      exit 1
    fi
  fi
done

if cmake --version >/dev/null  ; then
  echo "Extracting files..."
  tar xf "$ARCHIVE.tar.gz" || exit

  cmake -S $ARCHIVE -B test-build || exit
  cmake --build test-build || exit
  cd test-build
  ctest
else
  echo "Please install cmake"
fi
