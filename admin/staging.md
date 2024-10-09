Updating the Log4cxx web site
===================

This document describes the steps used to update Log4cxx web site
using 1.3.0 as an example Log4cxx version.

Prerequisites
----------

* The documentation changes have been committed to the log4cxx source code repository
* Doxygen 1.9.6 in available on your system
* APR and APR-Util are available on your system

Steps to update the Log4cxx web site
-----
 
1. Use Doxygen to generate the HTML, PNG, JS and CSS files
    - `git clone https://github.com/apache/logging-log4cxx /tmp/log4cxx`
    - `cmake -B /tmp/build -S /tmp/log4cxx -DBUILD_SITE=on`
    - `cmake --build /tmp/build -t doc_doxygen`
1. Check out the `asf-staging` branch of `logging-log4cxx-site`
    - `git clone https://github.com/apache/logging-log4cxx-site /tmp/log4cxx-site`
    - `cd /tmp/log4cxx-site`
    - `git checkout asf-staging`
1. Remove the previously generated files from the web site working directory
    - `git rm 1.3.0`
1. Move the newly generated files to the web site working directory
    - `mv /tmp/build/src/site/html 1.3.0`
    - `git add 1.3.0`
1. Push the `asf-staging` branch to Github and wait a bit
    - `git commit -m "Improved the ... documentation"`
    - `git push`
1. Check https://logging.staged.apache.org/log4cxx (after a minute or two)
    - are you seeing the correct releases page?


Steps to add a new version to the Log4cxx web site
-----
 
1. Use Doxygen to generate the HTML, PNG, JS and CSS files
    - `git clone https://github.com/apache/logging-log4cxx /tmp/log4cxx`
    - `cmake -B /tmp/build -S /tmp/log4cxx -DBUILD_SITE=on`
    - `cmake --build /tmp/build -t doc_doxygen`
1. Check out the `asf-staging` branch of `logging-log4cxx-site`
    - `git clone https://github.com/apache/logging-log4cxx-site /tmp/log4cxx-site`
    - `cd /tmp/log4cxx-site`
    - `git checkout asf-staging`
1. Move the generated files to the web site working directory
    - `mv /tmp/build/src/site/html /tmp/log4cxx-site/1.3.0`
1. Update the symbolic links in the base of the web site working directory
    - `cd /tmp/log4cxx-site`
    - `rm latest_stable old_stable`
    - `ln -s 1.3.0 latest_stable`
    - `ln -s 1.2.0 old_stable`
1. Update `.htaccess` so the final `RewriteRule` redirects to the new version
    - `RewriteRule ^(.*)$     /log4cxx/1.3.0/$1      [R=temp,L]`
1. Push the `asf-staging` branch to github and wait a bit 
    - `git add 1.3.0 latest_stable old_stable .htaccess`
    - `git commit -m "Add the 1.3.0 documentation"`
    - `git push`
1. Check https://logging.staged.apache.org/log4cxx (after a minute or two)
    - Are you seeing the new pages?
    - Download links for the new version should (at this point) not work

