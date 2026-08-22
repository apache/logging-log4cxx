Releasing a Log4cxx version
===================

This document lists the steps that must be performed to release Log4cxx
using 1.8.1 as the example.

Prerequisites
----------

* The version number (in src/cmake/projectVersionDetails.cmake) has been updated
* The change log (in src/site/markdown/change-report-gh.md) is up-to-date.
* The web-site for the new version has been published to https://logging.staged.apache.org/log4cxx (using [this procedure](staging.md) )
* An e-mail has been sent to dev@logging.apache.org announcing the intention to release
* Your e-mail client can send mail from your `@apache.org` address. (Refer: https://eventmesh.apache.org/community/how-to-use-email/)
* You have installed packages for git, svn, and the GitHub client CLI (gh) on your system

Steps
-----

1. Remove the old artifacts from svn
    - `cd $HOME`
    - `svn co https://dist.apache.org/repos/dist/dev/logging -N apache-dist-logging-dev`
    - `cd apache-dist-logging-dev`
    - `svn up log4cxx`
    - `cd log4cxx`
    - `svn delete *`
1. Tag HEAD as the release candidate (with the 'logging-log4cxx' source code tree root as the working directory)
    - `git checkout master`
    - `git pull`
    - `git tag v1.8.1-RC1`
    - `git push origin tag v1.8.1-RC1`
1. Download the packaged release files from Github (with the 'logging-log4cxx' source code tree root as the working directory)
    - `sh admin/generate_and_download.sh 1.8.1 master "$HOME/apache-dist-logging-dev"`
1. Send the 8 new artifacts to svn
    - `cd $HOME/apache-dist-logging-dev/log4cxx`
    - `mv release_files 1.8.1`
    - `svn add 1.8.1`
    - `svn commit -m 'log4cxx 1.8.1'`
    - check https://dist.apache.org/repos/dist/dev/logging/log4cxx
1. Raise a vote on the mailing list (dev@logging.apache.org)
   - Using [this template](MailTemplate.txt)
   - Set the e-mail to `Plain text mode`
1. Wait 72 hours (the minimum)
1. When the vote has 3 or more +1's, announce the result
   - Using [this template](MailTemplate.Result.txt)
   - Enter the name of each PMC member that voted
1. Get artifacts up to https://downloads.apache.org/logging/log4cxx/
    - `svn move -m "Release log4cxx 1.8.1" https://dist.apache.org/repos/dist/dev/logging/log4cxx/1.8.1   https://dist.apache.org/repos/dist/release/logging/log4cxx/`
1. Tag the released version
    - `git checkout v1.8.1-RC1`
    - `git tag rel/v1.8.1`
    - `git push origin tag rel/v1.8.1`
1. Enter the release date in `src/site/markdown/change-report-gh.md`
    - Commit the change
    - Update the staged web site using [the update procedure](staging.md)
1. Check the staged web site (https://logging.staged.apache.org/log4cxx) is ready to go live
    - Are you are seeing the release date on changelog?
    - Do the links on download page work?
1. Make the new version of the web site live.
    - `git clone https://github.com/apache/logging-log4cxx-site /tmp/log4cxx-site`
    - `cd /tmp/log4cxx-site`
    - `git fetch origin asf-staging`
    - `git checkout asf-site`
    - `git config pull.rebase true`
    - `git pull`
    - `git rebase origin/asf-staging`
    - `git push origin asf-site`
1. Check https://logging.apache.org/log4cxx (after a minute or two)
    - Are you seeing the new pages?
    - Do the download links now work?
1. Announce the release to the mailing lists (announce@apache.org, dev@logging.apache.org)
   - Using [this template](MailTemplate.Announce.txt)
   - Send the mail using your `@apache.org` account
   - Set the e-mail to `Plain text mode`
1. Add the release to the Apache Reporter System at https://reporter.apache.org/addrelease.html?logging
