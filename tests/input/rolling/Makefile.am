EXTRA_DIST = *.xml *.properties

# if we are building in a separate build tree, then copy all necessary files
all-local:
	@if test "$(top_srcdir)" != "$(top_builddir)"; then \
	  echo "Copying test suite data files ..." ; \
	  list='$(EXTRA_DIST)'; for file in $$list; do \
	    cp -p $(srcdir)/$$file . ; \
	  done \
	fi
