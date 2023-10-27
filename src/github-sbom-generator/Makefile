OUTDIR ?= bin
OUTFILE ?= $(OUTDIR)/github-sbom-generator

.PHONY: build

build: $(OUTFILE)

$(OUTFILE): $(OUTDIR)
	go build -o $@ .

$(OUTDIR):
	mkdir -p $@