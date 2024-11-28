#!/bin/sh

set -e

VERSION=$1
if [ -z "$VERSION" ] ; then
  VERSION=1.3.1
fi

if [ -z "$STAGE" ] ; then
  STAGE=dev # Alternatively release
fi

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
