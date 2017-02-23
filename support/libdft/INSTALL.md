# libdft: Installation Instructions

This piece of software, including this file is offered as-is, without warranty
of any kind. Read the top level [licence file](LICENSE) for the exact terms.

## Steps for compiling libdft
The simplest way to compile this package is:

  1. Extract the latest Pin build. Assuming that it was extracted in
     `/usr/src/pin`, we shall refer to that path as Pin's root path
      from now on.
  2. Type `export PIN_ROOT=/usr/src/pin` to set the environment
     variable PIN_ROOT to the root path of Pin. Replace `/usr/src/pin`
     with *your* Pin root path.
  3. `cd` to the directory [`src/`](src), which contains the source code of libdft,
     and type `make` to compile the package (i.e., the libdft library)
  4. `cd` to the directory [`tools/`](tools) and type `make tools` to compile the
     accompanying tools (e.g., `nullpin`, `libdft`, `libdft-dta`, etc.).
  5. You can remove the program binaries and object files from [`src/`](src)
     and [`tools/`](tools) by typing `make clean' on the respective directory.

## Supported platforms
libdft has been successfully tested with:

  * All Debian GNU/Linux versions starting with v5 (lenny).
    In principle it should also work on any other Linux distribution.
  * Intel Pin v2.12-v2.14
  * gcc/g++ 4.4.x-4.9.x
