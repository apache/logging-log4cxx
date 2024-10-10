Releasing a Log4cxx version
===================

This document lists the steps that must be performed to release Log4cxx
using 1.3.0 as the example.

Prerequisites
----------

* The version number (in src/cmake/projectVersionDetails.cmake) has been updated
* The change log (in src/site/markdown/change-report-gh.md) is up-to-date.
* The web-site for the new version has been published to https://logging.staged.apache.org/log4cxx (using [this procedure](staging.md) )
* An e-mail has been sent to dev@logging.apache.org announcing the intention to release
* Your public key is available in [Apache Logging KEYS file](https://dist.apache.org/repos/dist/release/logging/KEYS)

Steps
-----

1. Tag HEAD as the release candidate
    - `git checkout master`
    - `git push origin tag v1.3.0-RC1`
1. Remove the old artifacts from svn
    - `svn co https://dist.apache.org/repos/dist/dev/logging -N apache-dist-logging-dev`
    - `cd apache-dist-logging-dev`
    - `svn up log4cxx`
    - `cd log4cxx`
    - `svn delete *`
1. Download the latest release artifacts
    - The link to the packaged artifacts is available
      in the Github action log under the "Run action/upload-artifact" step of
      the "Generate release files" Github action.
      The log of the most recent commit can be accessed
      using the "Details" link in the pop-up window shown
      when the green tick is clicked.
    - `cd apache-dist-logging-dev/log4cxx`
    - `unzip "~/Downloads/Upload release files.zip"`
1. Sign release artifacts (Refer: https://infra.apache.org/release-signing.html)
    - `gpg --armor --output apache-log4cxx-1.3.0.zip.asc --detach-sig apache-log4cxx-1.3.0.zip`
    - `gpg --armor --output apache-log4cxx-1.3.0.tar.gz.asc --detach-sig apache-log4cxx-1.3.0.tar.gz`
1. Send the new artifacts to svn
    - `svn add *`
    - `svn commit -m 'log4cxx 1.3.0'`
    - check https://dist.apache.org/repos/dist/dev/logging/log4cxx
1. Raise a vote on the mailing list (dev@logging.apache.org)
   - Using [this template](MailTemplate.txt)
1. Wait 72 hours (the minimum)
1. When the vote has 3 or more +1's, announce the result
   - Using [this template](MailTemplate.Result.txt)
1. Get artifacts up to https://downloads.apache.org/logging/log4cxx/
    - `svn co https://dist.apache.org/repos/dist/release/logging -N apache-dist-logging-release`
    - `cd apache-dist-logging-release`
    - `svn up log4cxx`
    - `cd log4cxx`
    - `cp -r ../apache-dist-logging-dev/log4cxx 1.3.0`
    - `svn add 1.3.0`
    - `svn commit`
1. Make the new version of the web site live.
    - `git clone https://github.com/apache/logging-log4cxx-site /tmp/log4cxx-site`
    - `cd /tmp/log4cxx-site`
    - `git checkout asf-site`
    - `git rebase asf-staging`
    - `git push origin asf-site`
1. Tag the released version
    - `git checkout v1.3.0-RC1`
    - `git push origin tag rel/v1.3.0`
1. Announce the release to the mailing lists (announce@apache.org, dev@logging.apache.org)
   - Using [this template](MailTemplate.Announce.txt)

