# GitHub SBoM Generator

This is a simple tool that generates a simple SBoM from a provided github repository
and reference, either commit or tag.

It does not scan the repository or its contents; there are many tools that will do that for
you, e.g. [syft](https://github.com/anchore/syft).

Instead, it is provided with the repository and reference, and generates an SBoM pointing to that.

This is useful if you wish to include the GitHub repository itself as a reference in your SBoM.

Simple example:

```sh
$ github-sbom-generator generate --format spdx-json github.com/foo/bar#v1.2.1
```

## Building

A [Makefile](./Makefile) is provided to build the tool. Just run:

```sh
make build
```

and it will deposit the built file as `bin/github-sbom-generator`.

You can change the target outfile with `make build OUTFILE=/tmp/foo`, or just the output directory
while keeping the filename with `make build OUTDIR=/tmp`.

Note that the directory [bin/](./bin/) is already in the `.gitignore` file.
