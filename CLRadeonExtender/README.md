## CLRadeonExtender

This is mirror of the CLRadeonExtender project.

Original site is here [http://clrx.nativeboinc.org](http://clrx.nativeboinc.org).

Currently, this project is under construction/development.

CLRadeonExtender provides tools to develop software in low-level for the Radeon GPU's
compatible with GCN 1.0/1.1/1.2 architecture. Currently is two tools to develop
that software:

* clrxasm - the GCN assembler
* clrxdisasm - the GCN disassembler

Both tools can operate on two binary formats:

* the AMD Catalyst OpenCL program binaries
* the GalliumCompute (Mesa) program binaries

CLRadeonExtender not only provides basic tools to low-level development, but also
allow to embed own assembler with AMD Catalyst driver through CLwrapper.
An embedded assembler can be called from `clBuildProgram` OpenCL call
with specified option `-xasm`. Refer to README and INSTALL to learn about CLRXWrapper.

### System requirements

CLRadeonExtender requires:

* C++11 compliant compiler (Clang++ or GCC 4.7 or later)
* GNU make tool
* CMake system (2.6 or later)
* Threads support (for Linux, recommended NPTL)
* Unix-like (Linux or BSD) system or Windows system

Optionally, CLRXWrapper requires:

* libOpenCL.so or OpenCL.dll
* OpenCL ICD (for example from AMD Catalyst driver)
* AMD Catalyst driver.

### Compilation

To build system you should create a build directory in source code package:

```
mkdir build
```

and run:

```
cmake .. [cmake options]
```

Optional CMake configuration options for build:

* CMAKE_BUILD_TYPE - type of build (Release, Debug, GCCSan, GCCSSP).
* CMAKE_INSTALL_PREFIX - prefix for installation (for example '/usr/local')
* BUILD_32BIT - build also 32-bit binaries
* BUILD_TESTS - build all tests
* BUILD_SAMPLES - build OpenCL samples
* BUILD_DOCUMENTATION - build project documentation (doxygen, unix manuals, user doc)
* BUILD_DOXYGEN - build doxygen documentation
* BUILD_MANUAL - build Unix manual pages
* BUILD_CLRXDOC - build CLRX user documentation
* NO_STATIC - no static libraries
* OPENCL_DIST_DIR - an OpenCL directory distribution installation (optional)

You can just add one or many of these options to cmake command:

```
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
```

After creating Makefiles scripts you can compile project:

`make` or `make -jX` - where X is number of processors.

After building you can check whether project is working (if you will build tests):

```
ctest
```

Creating documentation will be done by this command
(if you will enable a building documentation, required for version 0.1):

```
make Docs
```

### Installation

Installation is easy. Just run command:

```
make install
```


### Usage

Usage of the clrxasm is easy:

```
clrxasm [-o outputFile] [options] [file ...]
```

If no file specified clrxasm read source from standard input.

Useful options:

* -g DEVICETYPE - device type ('pitcairn', 'bonaire'...)
* -A ARCH - architecture ('gcn1.0', 'gcn1.1' or 'gcn1.2')
* -b BINFMT - binary format ('amd', 'amdcl2', 'gallium', 'rawcode')
* -w - suppress warnings

Usage of the clrxdisasm:

```
clrxdisasm [options] [file ...]
```

and clrxdisasm will print a disassembled code to standard output.

Useful options for clrxdisasm:

* -a - print everything (not only code, but also kernels and their metadatas)
* -f - print floating points
* -h - print hexadecimal instruction codes
* -g DEVICETYPE - device type ('pitcairn', 'bonaire'...)
* -A ARCH - architecture ('gcn1.0', 'gcn1.1' or 'gcn1.2')

A CLRX assembler accepts source from disassembler.
