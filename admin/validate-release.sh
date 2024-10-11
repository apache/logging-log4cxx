#!/bin/sh

set -e

VERSION=$1
if [ -z "$VERSION" ] ; then
  VERSION=1.3.0
fi

if [ -z "$BASE_DL" ] ; then
  BASE_DL=https://dist.apache.org/repos/dist/dev/logging/log4cxx
fi
if [ -z "$ARCHIVE" ] ; then
  ARCHIVE=apache-log4cxx-$VERSION
fi
if [ -z "$TEST_DIRECTORY" ] ; then
  TEST_DIRECTORY=/tmp/log4cxx
fi

test -d "$TEST_DIRECTORY" || mkdir "$TEST_DIRECTORY"
cd "$TEST_DIRECTORY"

FULL_DL="$BASE_DL/$ARCHIVE"

for EXT in "tar.gz" "zip" ; do
  wget "$FULL_DL.$EXT" || exit $?
  wget "$FULL_DL.$EXT.asc" || exit $?
  for SUM in "sha512" "sha256"; do
    wget "$FULL_DL.$EXT.$SUM" || exit $?
  done
done
for SUM in "sha512" "sha256"; do
  echo "Validating $SUM checksum..."
  "${SUM}sum" --check  "$ARCHIVE.$EXT.$SUM" || exit $?
done

for EXT in "tar.gz" "zip" ; do
  echo "Validating signature..."
  gpg --verify "$ARCHIVE.$EXT.asc" || exit $?
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

