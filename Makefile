all: image

IMAGE ?= lfedge/eve-build-tools:latest
TOOLS ?= $(wildcard src/*)

.PHONY: all image list tools test FORCE

image:
	docker build -t $(IMAGE) .

list:
	@echo $(TOOLS)

tools: $(TOOLS)

$(TOOLS): FORCE
	make -C $@ build

test:

test-%: FORCE
	make -C $% test

FORCE:
