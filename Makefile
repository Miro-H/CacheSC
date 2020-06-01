SUBDIRS := src

TARGETS := all clean rebuild

$(TARGETS): $(SUBDIRS)

.PHONY: all $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)
