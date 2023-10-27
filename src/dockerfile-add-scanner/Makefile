OUTDIR ?= bin
OUTFILE ?= $(OUTDIR)/dockerfile-add-scanner

.PHONY: build test

build: $(OUTFILE)

$(OUTFILE): $(OUTDIR)
	go build -tags dfaddgit -o $@ .

$(OUTDIR):
	mkdir -p $@

test:
	go test -v ./...

