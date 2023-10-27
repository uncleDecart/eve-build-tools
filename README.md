# EVE Build Tools

This repository contains tools used for building parts of the [EVE](https://github.com/lf-edge/eve) ecosystem. The tools in here can
be used directly, or can be runas part of a publicly available [Docker image](https://hub.docker.com/r/lfedge/eve-build-tools).
There is a single image containing all of the tools.

## Build

* To build the Docker image, run `make image`, or just `docker build -t <tag> .`
* To build an individual tool locally, run `make <toolname>`
* To build all of the tools locally, run `make tools`
* To list the available tools, run `make list`

## Adding a new tool

Each tool should be in its own directory, under [`src/`](./src/). This makes the build simpler,
with actual source under `src/`, and tooling, like the Makefile and Dockerfile, as well as documentation
like the README, in the root directory.

In addition, each tool should have a Makefile, with the target `build` to build locally.

