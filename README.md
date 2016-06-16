Meriken's Tripcode Engine [![Build Status](https://travis-ci.org/meriken/merikens-tripcode-engine-v3.svg?branch=master)](https://travis-ci.org/meriken/merikens-tripcode-engine-v3) [![GPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/meriken/merikens-tripcode-engine-v3/master/LICENSE)
=========================

This repository was moved from https://github.com/meriken/merikens-tripcode-engine

"Meriken's Tripcode Engine" is a cross-platform application designed to generate custom/vanity tripcodes at maximum speed. 
It is arguably the fastest and most powerful program of its kind. It makes effective use of available computing power of CPUs and GPUs, 
and the user can specify flexible regex patterns for desired tripcodes. It features highly optimized, extensively parallelized 
implementations of bitslice DES and SHA-1 for OpenCL, AMD GCN, NVIDIA CUDA, and Intel SSE2/AVX/AVX2.

## Downloads

### Precompiled Binaries for Windows
* [MerikensTripcodeEngine_3.2.12_English_Windows.zip]( http://bit.ly/1tdRqRn )<sup>[1](#myfootnote1)</sup>
* [MerikensTripcodeEngine_3.2.11_English_Windows.zip]( http://bit.ly/20YC2D0 )<sup>[1](#myfootnote1)</sup>
* [MerikensTripcodeEngine_3.2.0_English_Windows.zip]( http://j.mp/27EmyJi )<sup>[2](#myfootnote2)</sup>
* [MerikensTripcodeEngine_2.1.2_English.zip]( http://j.mp/26rh3x7 )<sup>[2](#myfootnote2)</sup>

<a name="myfootnote1">1</a>: NVIDIA Display Driver Version 362.61 or later is required if you are using an NVIDIA video card.<br>
<a name="myfootnote1">2</a>: NVIDIA Display Driver Version 352.78 or later is required if you are using an NVIDIA video card.<br>

### Ubuntu Personal Package Archives

* [Meriken's PPA]( https://launchpad.net/~meriken/+archive/ubuntu/ppa )

### Arch Linux User Repository

* [merikens-tripcode-engine-v3-git]( https://aur.archlinux.org/packages/merikens-tripcode-engine-v3-git/ )

### Source Codes
* [merikens-tripcode-engine-v3-v3.2.14.tar.gz]( http://bit.ly/merikens-tripcode-engine-v3-v3_2_14_tar_gz )
* [merikens-tripcode-engine-v3-v3.2.13.tar.gz]( http://bit.ly/merikens-tripcode-engine-v3-v3_2_13_tar_gz )

## Performance

Here are actual speeds the author achieved with this tripcode generator:

* AMD Radeon HD 7990 **1022MH/s** (descrypt; 1250mV +20% 1180MHz)
* NVIDIA GeForce GTX 980 Ti **996MH/s** (descrypt; 110% +250MHz)
* AMD Radeon HD 290X **647M tripcode/s** (descrypt; +100mV +50% 1074MHz)
* AMD Radeon HD 7970 **408M tripcode/s** (descrypt; 1000MHz)

Currently [MTY CL][2] is the only practical alternative to this program, and this program runs much faster than MTY CL in most cases as the folowing benchmarks show:

```
Meriken's Tripcode Engine 2.0.6: 427M tripcode/s
MTY CL 0.52: 285M tripcode/s
Tripcode Explorer: 16M tripcode/s

Hardware and Software Configuration:
OS: Microsoft Windows 7 SP1 Professional
CPU: Intel Core i7-3770K @ 3.5GHz
GPU: Gigabyte Radeon HD 7970 @ 1060MHz
Display Driver: AMD Catalyst 15.7.1
Target Pattern: ^TEST//
```

[2]: https://github.com/madsbuvi/MTY_CL

## Donations

I would really appreciate donations as it is quite expensive to keep buying hardware for testing.
I am also working on the English version of my tripcode search service and would like to add more servers.

* PayPal: `meriken.ygch.net@gmail.com`
* Bitcoin: `1BZrWADRhLr9DyQYYRJhRcmudE3vntT5em`

## Supported Video Cards

* AMD Radeon HD 5xxx or later
* CUDA-enabled NVIDIA video card with compute capability of 2.0 or higher<sup>[3](#myfootnote3)</sup>

<a name="myfootnote3">3</a>: [CUDA GPUs]( https://developer.nvidia.com/cuda-gpus )<br>

## Windows

### Building on Windows

You need the following tools to build Meriken's Tripcode Engine.

* Visual Studio 2015 Community
* CUDA Toolkit 8.0
* AMD APP SDK 3.0
* YASM **1.2.0** (Do not use YASM 1.3.0!)

I recommend that the source archive be extracted at the root of a drive and that the environment variable `PreferredToolArchitecture` be set to `x64` on 64-bit operating systems. This program uses Boost 1.61.0 and Boost.Process 0.5. Make sure to extract `BoostPackages/boost_1_61_0.7z` and run `BoostPackages/BuildBoostForVisualStudio.bat` before building `VisualStudio/MerikensTripcodeEngine.sln`.

There are several configurations. If you are using a 64-bit operating system, you need to build both 32-bit and 64-bit executables. Please note that NVIDIA-optimized versions take **extremely** long time to build.

### Dependencies

You need the following software installed in order to run the application:

* [AMD Radeon Desktop Video Card Driver][4]
  (if you are using an AMD graphics card)
* [NVIDIA Display Driver Version 362.61 or later][5]
  (if you are using an NVIDIA graphics card)

[4]: http://support.amd.com/en-us/download
[5]: http://www.nvidia.com/Download/index.aspx?lang=en-us

### Usage

Specify search patterns in `patterns.txt` and run either
`MerikensTripcodeEngine.exe`, if you are using a 32-bit operating system, or
`MerikensTripcodeEngine64.exe`, if you are using a 64-bit operating system.
Matching tripcodes will be displayed and saved in `tripcodes.txt`. See "Example of 'patterns.txt'" and "Options" below.

Alternatively, you can extract one of the NVIDIA-optimized versions in `MerikensTripcodeEngine64_NVIDIA.7z` and use it instead if you are using an NVIDIA video card with the compute capability of 5.0 or greater on a 64-bit operating system. Please note that these binaries are exremely huge.

## Linux, Mac OS X,  and Other POSIX Systems

### Building on POSIX Systems

You should be able to build and run this application on any POSIX-compliant operating systems. You need the following tools to build Meriken's Tripcode Engine.

* C++11-compliant compiler (g++-4.8 or later/clang++-3.5 or later; g++ is recommended.)
* OpenCL 1.2 SDK such as AMD APP SDK and NVIDIA CUDA Toolkit (if you are using an AMD/NVIDIA video card.)
* CUDA Toolkit 7.5+ (optional for optimal performance if you are using an NVIDIA video card.)

You should be able to build and install everything by running `./BuildAll.sh --install`. You can specify the following options for `BuildAll.sh`:

*    --with-toolset=gcc
*    --with-toolset=clang
*    --enable-cuda
*    --disable-cuda
*    --enable-opencl
*    --disable-opencl
*    --enable-cuda-des-multiple-kernels-mode
*    --english-version
*    --japanese-version
*    --run-tests
*    --install
*    --rebuild

Please note that NVIDIA-optimized versions (`--enable-cuda-des-multiple-kernels-mode`) take **extremely** long time to build.

#### Installation Instructions for Ubuntu 16.04 LTS

The easiest way is to download the application from my PPA without CUDA support:

```
$ sudo add-apt-repository ppa:meriken/ppa
$ sudo apt update && sudo apt install merikens-tripcode-engine
```

If you are using the 64-bit version of the OS, you can use the CUDA-compatible package instead:

```
$ sudo add-apt-repository ppa:meriken/ppa
$ sudo apt update && sudo apt install merikens-tripcode-engine-cuda
```

For optimal performance with NVIDIA video cards, however, you need to build the application yourself.


```
$ git clone https://github.com/meriken/merikens-tripcode-engine-v3
$ cd merikens-tripcode-engine-v3
$ sudo apt-get update && sudo apt-get install nvidia-cuda-toolkit gcc-4.9 g++-4.9 p7zip-full libbz2-dev python2.7-dev mesa-common-dev
$ ./BuildAll.sh --enable-cuda-des-multiple-kernels-mode --install
```

Unfortunately, AMD Proprietary (fglrx) Driver is not available for Ubuntu 16.04 LTS, so you cannot use AMD video cards with this application. If you would like to use an AMD graphics card, please stick to Ubuntu 14.04 LTS.

#### Installation Instructions for Ubuntu 14.04 LTS

The only differences from Ubuntu 16.04 LTS are that the `merikens-tripcode-engine-cuda` package is not available and that you have to install CUDA Toolkit 7.5+ manually if you want to build the application with CUDA support.

```
$ git clone https://github.com/meriken/merikens-tripcode-engine-v3
$ cd merikens-tripcode-engine-v3
(Install CUDA Toolkit...)
$ sudo apt-get update && sudo apt-get install p7zip-full libbz2-dev python2.7-dev mesa-common-dev
$ ./BuildAll.sh --install
```

#### Build Instructions for Arch Linux 201604

You can download the application from the AUR. OpenCL support is enabled by default, but you need to install CUDA Toolkit 7.5 or later manually for CUDA support.

```
$ git clone https://aur.archlinux.org/merikens-tripcode-engine-v3-git.git
$ cd merikens-tripcode-engine-v3-git
$ makepkg -si
```

#### Build Instructions for FreeBSD 10.3

You need to build the application with GCC.

```
$ git clone https://github.com/meriken/merikens-tripcode-engine-v3
$ cd merikens-tripcode-engine-v3
$ sudo pkg install gcc
$ export LD_LIBRARY_PATH="/usr/local/lib/gcc48"
$ sudo pkg install p7zip
$ ./BuildAll.sh --with-toolset=gcc --install
```

#### Build Instructions for Mac OS X 10.10

Please install [Homebrew]( http://brew.sh/ ) first if you want to follow these instructions.

```
$ git clone https://github.com/meriken/merikens-tripcode-engine-v3
$ cd merikens-tripcode-engine-v3
$ brew install p7zip
$ ./BuildAll.sh --install
```

### Dependencies

You need the following software installed in order to run the application:

* AMD Proprietary Linux Graphics Driver (if you are using an AMD graphics card)
* NVIDIA Display Driver Version 352.78 or later (if you are using an NVIDIA graphics card)

### Usage

Specify search patterns in `patterns.txt` and run `MerikensTripcodeEngine`.
Matching tripcodes will be displayed and saved in `tripcodes.txt`.
See "Example of 'patterns.txt'" and "Options" below.

## Example of "patterns.txt"

```
# Meriken's Tripcode Engine English
# Copyright (c) 2011-2016 !/Meriken/. <meriken.ygch.net@gmail.com>
#
# - Specify only one pattern in each line.
# - Patterns must be at least 5 characters in length.
# - Patterns that are too long will be ignored.
# - Strings after '#' are treated as comments.



# Specify non-regex patterns after the "#noregex" directive.
# You can only use [A-Za-z0-9./] for patterns.

#noregex

TEST/                   # Matches "!TEST/UH3.F", "!TEST/ZXVew", etc.



# Specify regex patterns after the "#regex" directive.
# The following operators and specifiers are available for use:
# 
#     ^ $ () | [] [^] . + * ? \ {n} {m,n} \n
#     [:alpha:] [:upper:] [:lower:] [:digit:] [:alnum:] [:punct:]
# 
# It is encouraged to use '^' whenever possible to achieve maximum
# search speed.

#regex

#^TEST/                 # Matches "!TEST/UH3.F", "!TEST/ZXVew", etc.
#/TEST$                 # Matches "!15ycs/TEST", "!wtra5/TEST", etc.
#/TEST/                 # Matches "!y/TEST/5uj", "!anj/TEST/.", etc.
#^[0-9]*$               # Matches "!8710915015", "!9104552720", etc.
#^([:upper:]{5})\1$     # Matches "!IOPAFIOPAF", "!UIABTUIABT", etc.
#^[Mm]eriken[:punct:]   # Matches "!meriken/u6", "!Meriken.qe", etc.



#ignore
Lines between "#ignore" are "#endignore" will be ignored.
#endignore



# You cannot specify a pattern in the last line.
```

## Options

**-g** : Use GPUs as search devices. (This option can be used in combination with "-c".)

**-d** [device number] : Specify a GPU to use.

**-c** : Use CPUs as search devices. (This option can be used in combination with "-g".)

**-l** [length of tripcodes] : Specify either 10 or 12. (Please note that you can use 12 character tripcodes only at 2ch.net.)

**-x** [number of blocks/SM] : Specify the number of blocks per SM (1 <= n <= 256) for CUDA devices.

**-t** [number of threads] : Specify the number of CPU search threads.

**-o** [output file] : Specify an output file.

**-f** [input file] : Specify an input file.

**--use-one-and-two-byte-characters-for-keys** : Use Shift-JIS characters for keys.

**--disable-gcn-assembler** : Disable GCN assembler and use OpenCL kernels instead.

## Support Threads

I occasionaly create support threads for this program on 4chan to receive direct feedback from its users. The following are archives of the past support threads:

* [Meriken's Tripcode Engine English (9/26/2013)]( http://archive.rebeccablacktech.com/g/thread/37003452 )
* [Meriken's Tripcode Engine English No. 2 (10/2/2013)]( http://archive.rebeccablacktech.com/g/thread/37126997 )
* [Meriken's Tripcode Engine English No. 3 (10/13/2015)]( http://archive.rebeccablacktech.com/g/thread/50803429 ) 
* [Meriken's Tripcode Engine English No. 4 (10/17/2015)]( https://archive.rebeccablacktech.com/g/thread/50871258 )
* [Meriken's Tripcode Engine English No. 5 (4/24/2016)]( https://archive.rebeccablacktech.com/g/thread/54208823 )
* [Meriken's Tripcode Engine English No. 6 (5/14/2016)]( http://boards.4chan.org/g/thread/54553624 )
* [Meriken's Tripcode Engine No. 7 (5/20/2016)]( http://boards.4chan.org/g/thread/54662329 )
* [Meriken's Tripcode Engine No. 8 (5/21/2016)]( http://boards.4chan.org/g/thread/54679797 )
* [Meriken's Tripcode Engine No. 9 (5/29/2016)]( http://boards.4chan.org/g/thread/54807160 )
* [Meriken's Tripcode Engine No. 10 (6/4/2016)]( http://boards.4chan.org/g/thread/54906403 )

## Source Code

The source code is hosted on GitHub:

[https://github.com/meriken/merikens-tripcode-engine-v3]( https://github.com/meriken/merikens-tripcode-engine-v3 )
	  
## Miscellaneous Notes

Please feel free to contact the author at [meriken.ygch.net@gmail.com]( mailto:meriken.ygch.net@gmail.com ) for feedback, bug reports, suggestions, etc.

"Meriken's Tripcode Engine" is part of the GUI-based, network-capable [Meriken's Tripcode Generator]( http://meriken.ygch.net/programming/merikens-tripcode-generator/ ), which is intended primarily for users of 2ch.net in Japan. If Japanese does not discourage you, check out the original application as well as [Meriken's Tripcode Yggdrasil]( http://tripcode.ygch.net/yggdrasil/ ), a web-based distributed tripcode generation service.

## License

Meriken's Tripcode Engine is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Meriken's Tripcode Engine is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Meriken's Tripcode Engine.  If not, see <http://www.gnu.org/licenses/>.

Copyright © 2016 ◆/Meriken/.
