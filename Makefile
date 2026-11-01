.DEFAULT_GOAL := all
.PHONY: all
all:
	$(MAKE) -C yamora
%:
	$(MAKE) -C yamora $@
