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
1. Download the packaged release files from Github
    - Open https://github.com/apache/logging-log4cxx/commits/v1.3.0-RC1 in your web browser
    - Click the green tick mark on the top commit
        - The `All checks have passed` pop-up window will display
    - Click the "Details" link on the row next to `Generate release files / Package code for release`
        - The `Package for release` log window will display
    - Click the `>` to the left of `Run action/upload-artifact`
        - The numbered steps will display
    - Click the link next to `Artifact download URL:`
        - The browser will download the file `Upload release files.zip` onto your system
1. Unpack the release files using these commands
    - `cd apache-dist-logging-dev/log4cxx`
    - `unzip "$HOME/Downloads/Upload release files.zip"`
1. Sign release artifacts (Refer: https://infra.apache.org/release-signing.html) (with `apache-dist-logging-dev/log4cxx` as the working directory)
    - `gpg --armor --output apache-log4cxx-1.3.0.zip.asc --detach-sig apache-log4cxx-1.3.0.zip`
    - `gpg --armor --output apache-log4cxx-1.3.0.tar.gz.asc --detach-sig apache-log4cxx-1.3.0.tar.gz`
1. Send the new artifacts to svn (with `apache-dist-logging-dev/log4cxx` as the working directory)
    - `svn add *`
    - `svn commit -m 'log4cxx 1.3.0'`
    - check https://dist.apache.org/repos/dist/dev/logging/log4cxx
1. Raise a vote on the mailing list (dev@logging.apache.org)
   - Using [this template](MailTemplate.txt)
1. Wait 72 hours (the minimum)
1. When the vote has 3 or more +1's, announce the result
   - Using [this template](MailTemplate.Result.txt)
1. Get artifacts up to https://downloads.apache.org/logging/log4cxx/
    - `svn move -m "Release log4cxx 1.3.0" https://dist.apache.org/repos/dist/dev/logging/log4cxx   https://dist.apache.org/repos/dist/release/logging/log4cxx/1.3.0`
1. Tag the released version
    - `git checkout v1.3.0-RC1`
    - `git push origin tag rel/v1.3.0`
1. Make the new version of the web site live.
    - `git clone https://github.com/apache/logging-log4cxx-site /tmp/log4cxx-site`
    - `cd /tmp/log4cxx-site`
    - `git checkout asf-site`
    - `git rebase asf-staging`
    - `git push origin asf-site`
1. Check https://logging.apache.org/log4cxx (after a minute or two)
    - Are you seeing the new pages?
    - Download links for the new version should now work
1. Announce the release to the mailing lists (announce@apache.org, dev@logging.apache.org)
   - Using [this template](MailTemplate.Announce.txt)

