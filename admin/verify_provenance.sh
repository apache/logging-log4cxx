#!/bin/sh

set -e

VERSION=$1
if [ -z "$VERSION" ] ; then
  VERSION=1.8.1
fi

if [ -z "$ARCHIVE" ] ; then
  ARCHIVE=apache-log4cxx-$VERSION
fi

if [ -z "$TEST_DIRECTORY" ] ; then
  TEST_DIRECTORY=/tmp/log4cxx-$VERSION
fi
for TYPE in tar.gz zip; do
  if ! test -f "$TEST_DIRECTORY/$ARCHIVE.$ARCHIVE_TYPE.sha512" ; then
    echo "$ARCHIVE.$TYPE.sha512 not found in $TEST_DIRECTORY"
    exit 1
  fi
done

WORKFLOW="package_code"

# Get the latest Run ID
RUN_ID=$(gh run list --workflow="$WORKFLOW.yml" --limit 1 --json databaseId --jq '.[0].databaseId')
if [ $? -ne 0 ]; then
  echo "Failed to find a $WORKFLOW run id"
  exit 1
fi
# Download the artifacts
echo "Downloading $WORKFLOW run $RUN_ID artifacts into '$TEST_DIRECTORY' ..."
gh run download "$RUN_ID" --dir "$TEST_DIRECTORY"

# Compare hash codes
echo "Comparing archive checksums"
cd "$TEST_DIRECTORY"
for TYPE in tar.gz zip; do
  if diff {,release_files/}$ARCHIVE.$TYPE.sha512 ; then
    echo "$ARCHIVE.$TYPE.sha512: OK"
  else
    echo "$ARCHIVE.$TYPE.sha512 is different"
    exit 1
  fi
done
