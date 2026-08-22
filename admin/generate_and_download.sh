#!/bin/sh

set -e

VERSION=$1
if [ -z "$VERSION" ] ; then
  VERSION=1.8.1
fi

BRANCH=$2
if [ -z "$BRANCH" ] ; then
  BRANCH=master
fi

ARTEFACT_DIRECTORY=$3
if [ -z "$ARTEFACT_DIRECTORY" ] ; then
  if [ "$BRANCH" == master ] ; then
    ARTEFACT_DIRECTORY="$HOME/apache-dist-logging-dev"
  else
    ARTEFACT_DIRECTORY="/tmp"
  fi
fi

WORKFLOW="package_code.yml"
echo "Triggering workflow..."
gh workflow run "$WORKFLOW" --ref "$BRANCH"

# Give GitHub a few seconds to register and start the run
sleep 8

# Get the latest Run ID
RUN_ID=$(gh run list --workflow="$WORKFLOW" --limit 1 --json databaseId --jq '.[0].databaseId')
echo "Tracked Run ID: $RUN_ID"

# Watch the progress in the console until it finishes
gh run watch "$RUN_ID"

# Download the artifacts
echo "Downloading artifacts into '$ARTEFACT_DIRECTORY/log4cxx' ..."
gh run download "$RUN_ID" --dir "$ARTEFACT_DIRECTORY/log4cxx"
