#!/bin/bash
#
set -e

# Determine the version and build timestamp
VERSION=$(grep -Po '(?<=set\(log4cxx_VER ")(.*)(?="\))' src/cmake/projectVersionDetails.cmake)
if ! echo "$VERSION" | grep -Pq '^\d+\.\d+\.\d+$'; then
  echo Invalid version number: "$VERSION" >& 2
  exit 1
fi

OUTPUT_TIMESTAMP=$(grep -Po '(?<=set\(log4cxx_OUTPUT_TIMESTAMP ")(.*)(?="\))' src/cmake/projectVersionDetails.cmake)
if ! echo "$OUTPUT_TIMESTAMP" | grep -Pq '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'; then
  echo Invalid build timestamp: "$OUTPUT_TIMESTAMP" >& 2
  echo Run '`'date -u +%Y-%m-%dT%H:%M:%SZ'`' to generate it
  exit 1
fi

# Build directory containing temporary files
#
build=CMakeFiles

# Directory containing the distribution archives
#
dist="$build/dist"

# Create source directory
mkdir -p "$build"
OUTPUT_DIR="$build/apache-log4cxx-$VERSION"
if [ -f "$OUTPUT_DIR" ]; then
  if [ ! -d "$OUTPUT_DIR" ]; then
    echo File "$OUTPUT_DIR" is not a directory >& 2
    exit 1
  fi
  if [ ! -z "$(ls -A "$OUTPUT_DIR")" ]; then
    echo Directory "$OUTPUT_DIR" is not empty >& 2
    exit 1
  fi
fi
mkdir -p "$OUTPUT_DIR"

# Copy files to directory
cp -r \
  CMakeLists.txt \
  KEYS \
  INSTALL \
  LICENSE \
  NOTICE \
  README.md \
  src \
  liblog4cxx.pc.in \
  liblog4cxx-qt.pc.in \
  "$OUTPUT_DIR"
rm -r "$OUTPUT_DIR"/src/main/abi-symbols

# Create TAR file
#
# See https://reproducible-builds.org/docs/archives/ for reproducibility tips
TAR_ARCHIVE="$dist/apache-log4cxx-$VERSION.tar.gz"
echo 'Tar version:'
tar --version | sed -e 's/^/\t/'
echo 'Gzip version:'
gzip --version  | sed -e 's/^/\t/'
if [ -f "$TAR_ARCHIVE" ]; then
  echo Archive "$TAR_ARCHIVE" already exists >& 2
  exit 1
fi

tar --transform="s!^$OUTPUT_DIR!apache-log4cxx-$VERSION!" \
  --mtime="$OUTPUT_TIMESTAMP" \
  --owner=0 --group=0 --numeric-owner \
  --sort=name \
  --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
  --create --gzip --file "$TAR_ARCHIVE" "$OUTPUT_DIR"

echo -e Tar archive: "$TAR_ARCHIVE"

# Create ZIP file
#
# See https://reproducible-builds.org/docs/archives/ for reproducibility tips
# Change the mtime of all files
ZIP_ARCHIVE="$dist/apache-log4cxx-$VERSION.zip"
echo 'Zip version:'
zip --version | sed 's/^/\t/'
if [ -f "$ZIP_ARCHIVE" ]; then
  echo Archive "$ZIP_ARCHIVE" already exists >& 2
  exit 1
fi

find "$OUTPUT_DIR" -exec touch --date="$OUTPUT_TIMESTAMP" -m {} +
# Sort files and zip.
(
  cd "$build"
  find apache-log4cxx-$VERSION -print0 |
  LC_ALL=C sort -z |
  xargs -0 zip -q -X dist/apache-log4cxx-$VERSION.zip
)

echo -e ZIP archive: "$ZIP_ARCHIVE"

# Generate hashes
(
  cd "$dist"
  for format in tar.gz zip; do
    sha256sum apache-log4cxx-$VERSION.$format > apache-log4cxx-$VERSION.$format.sha256
    sha512sum apache-log4cxx-$VERSION.$format > apache-log4cxx-$VERSION.$format.sha512
  done
)
