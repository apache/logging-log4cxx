EXTRA_DIST = UTF-* \
             ascii.log \
             latin1.log

# if we are building in a separate build tree, then copy all necessary files
all-local:
	@if test "$(top_srcdir)" != "$(top_builddir)"; then \
	  echo "Copying test suite data files ..." ; \
	  list='$(EXTRA_DIST)'; for file in $$list; do \
	    find $(srcdir) -name "$$file" -exec cp {} . ';' ; \
	  done \
	fi
