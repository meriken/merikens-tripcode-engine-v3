![image](https://github.com/TheProdigyLeague/merikens-tripcode-engine-v3/assets/30985576/7c5167f5-3107-45dc-9978-13df0571dae3)


# "Meriken's Tripcode Engine" 

Generator for custom and vanity social credit badges on cross-platforms. CPU and GPU overclocks the users regex patterns for their desired tripcode. It is extensively parallelized for implementing bitslices: DES, SHA-1, OpenCL, AMD GCN, NVIDIA CUDA, INTEL SSE2/AVX/AVX2, Genereic Arch-Agnostic, and crytpo functions written in C++. This allows the app to run on high end, multi-scaled GPU systems as Raspberry PI.

![image](https://github.com/TheProdigyLeague/merikens-tripcode-engine-v3/assets/30985576/e1c3f7c2-78f3-4a86-b148-bd35e251f01a)


## Table of Contents

* [Performance](#performance)
* [Donations](#donations)
* [Supported Video Cards](#supported-video-cards)
* [Windows](#windows)
* [Linux, Mac OS X, and Other POSIX Systems]( #linux-mac-os-x--and-other-posix-systems )
* [Example of "patterns.txt"](#example-of-patternstxt )
* [Options](#options)
* [Support Threads](#support-threads)
* [Source Code](#source-code)
* [Miscellaneous Notes](#miscellaneous-notes)
* [License](#license)

### Source Code

* [merikens-tripcode-engine-v3-v3.2.14.tar.gz]( http://bit.ly/merikens-tripcode-engine-v3-v3_2_14_tar_gz )

⚠️ This program is a MTY CL for running perf logs at fast rates. 

```bat
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

[madsbuvi](https://github.com/madsbuvi/MTY_CL)

~~## Donations I would really appreciate donations as it is quite expensive to keep buying hardware for testing. I am also working on the English version of my tripcode search service and would like to add more servers. * PayPal: `meriken.ygch.net@gmail.com` * Bitcoin: `1BZrWADRhLr9DyQYYRJhRcmudE3vntT5em`~~

[NVIDIA]( https://developer.nvidia.com/cuda-gpus )<br>

![image](https://github.com/TheProdigyLeague/merikens-tripcode-engine-v3/assets/30985576/709645d2-2b7b-4265-af48-d0172cd6c44a)


### Building on Windows

* Visual Studio 2015 Community
* CUDA Toolkit 8.0
* AMD APP SDK 3.0
* YASM **1.3.0**

💻 The source arhive is to be pre-packaged as `C:/root~$`  and the handler `env vars is set PreferredToolArchitecture_x64 os` Because, this boosts your compiler as `v-1.61.0 Boost.Process 0.5` to extract `BoostPackages/boost_1_61_0.7z`...Then, run `BoostPackages/BuildBoostForVisualStudio.bat` before pre-building `VisualStudio/MerikensTripcodeEngine.sln`. Indeed, there are several configs, but if you're using x64 os, then there's no need to build on x32 executables. 🤓 ⚠️ NVIDIA is optimized default with their disk partitioning. 

### Dependencies

Pre-installer application runner:

[Tech_Support]: http://support.amd.com/en-us/download
[NVIDIA_Manual]: http://www.nvidia.com/Download/index.aspx?lang=en-us

#### Usage

- Specify search patterns: `patterns.txt`
- `MerikensTripcodeEngine.exe | x32`
- `MerikensTripcodeEngine64.exe | x64`
- Matched tripcodes will be displayed as `tripcodes.txt`. See "Example of 'patterns.txt'" and "Options" below.
- Extract NVIDIA-optimized version as `MerikensTripcodeEngine64_NVIDIA.7z` because you're using an NVIDIA video card with computing capability of 5.0 > on x64 os. So, these `/bins/` are gargantuan.

### Building on POSIX Systems

Running this should be POSIX-compliant.

* C++11-compliant compiler
* G++v-4.8 >
* CLANG++v-3.5 >
* OpenCL 1.2 SDK, AMD, APP, SDK, and NVIDIA CUDA Toolkit 7.5+ (If using AMD/NVIDIA video card).

Once compiled, it should automatically build and install everything by default in `./BuildAll.sh --install | BuildAll.sh`

```bash
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
```

⚠️ NVIDIA-optimized versions (`--enable-cuda-des-multiple-kernels-mode`) take an **extremely** long time to build.

<hr>

![image](https://github.com/TheProdigyLeague/merikens-tripcode-engine-v3/assets/30985576/65abb202-7f78-4acf-a78c-c2ff437528d5)

<br>

#### Ubuntu 16.04 LTS

PPA CUDA support download:

```
$ sudo add-apt-repository ppa:meriken/ppa
$ sudo apt update && sudo apt install merikens-tripcode-engine
```

x64 OS, CUDA-compatible pkg:

```
$ sudo add-apt-repository ppa:meriken/ppa
$ sudo apt update && sudo apt install merikens-tripcode-engine-cuda
```

ソースビルド:

```
$ git clone https://github.com/meriken/merikens-tripcode-engine-v3
$ cd merikens-tripcode-engine-v3
$ sudo apt-get update && sudo apt-get install nvidia-cuda-toolkit gcc-4.9 g++-4.9 p7zip-full libbz2-dev python2.7-dev mesa-common-dev
$ ./BuildAll.sh --enable-cuda-des-multiple-kernels-mode --install
```

Note: AMD Proprietary (fglrx) Drive for Ubuntu 16.04 LTS cannot use AMD video cards with my App. So, if people use an AMD graphics card, use Ubuntu 14.04 LTS.

#### Ubuntu 14.04 LTS

```bash
$ merikens-tripcode-engine-cuda | Ubuntu 16.04 LTS -pkg --install CUDA_Toolkit-v-7.5++ -man` Building with application CUDA support.
$ git clone https://github.com/meriken/merikens-tripcode-engine-v3
$ cd merikens-tripcode-engine-v3
(Installing CUDA Toolkit...)
$ sudo apt-get update && sudo apt-get install p7zip-full libbz2-dev python2.7-dev mesa-common-dev
$ ./BuildAll.sh --install
```

#### Arch Linux 201604

Note: AUR OpenCL support is enabled by default with CUDA Toolkit 7.5++ support for later manning CUDA support.

```
$ git clone https://aur.archlinux.org/merikens-tripcode-engine-v3-git.git
$ cd merikens-tripcode-engine-v3-git
$ makepkg -si
```

#### FreeBSD 10.3

GCC build application:

```
$ git clone https://github.com/meriken/merikens-tripcode-engine-v3
$ cd merikens-tripcode-engine-v3
$ sudo pkg install gcc
$ export LD_LIBRARY_PATH="/usr/local/lib/gcc48"
$ sudo pkg install p7zip
$ ./BuildAll.sh --with-toolset=gcc --install
```

#### Mac OS X 10.10

Install [Homebrew]( http://brew.sh/ )

```
$ git clone https://github.com/meriken/merikens-tripcode-engine-v3
$ cd merikens-tripcode-engine-v3
$ brew install p7zip
$ ./BuildAll.sh --install
```

### Dependencies

Prerequisites:

* AMD Proprietary Linux Graphics Driver (If using an AMD graphics card).
* NVIDIA Display Driver Version 352.78 or later (If using NVIDIA graphics card).

### Usage

- Specify `patterns.txt` run `MerikensTripcodeEngine`.
- Matching tripcodes: `tripcodes.txt`.
~~- See "Example of 'patterns.txt'" and "Options" below.~~

## Example of "patterns.txt"

```
# Meriken's Tripcode Engine English
# Copyright (c) 2011-2016 !/Meriken/. <meriken.ygch.net@gmail.com>
# - Specify only one pattern in each line.
# - Patterns must be at least 5 characters in length.
# - Patterns that are too long will be ignored.
# - Strings after '#' are treated as comments.
# Specify non-regex patterns after the "#noregex" directive.
# You can only use [A-Za-z0-9./] for patterns.

#noregex

TEST

# Matches "!TEST/UH3.F", "!TEST/ZXVew"

# Specify regex patterns after "#regex" directive.
# The following operators and specifiers are available for use:
#     ^ $ () | [] [^] . + * ? \ {n} {m,n} \n
#     [:alpha:] [:upper:] [:lower:] [:digit:] [:alnum:] [:punct:]
# Use '^' to achieve maximum search speed.

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

# You cannot specify a pattern in Last Line.
```

![image](https://github.com/TheProdigyLeague/merikens-tripcode-engine-v3/assets/30985576/68ac9dfa-678d-4dfa-a9d6-fe2e651dd758)

## Options

**-g** : Uses GPUs as search devices. (This option can be used in combination with "-c").

**-d** [device number] : Specify a GPU to use.

**-c** : Uses CPUs as search devices. (This option can be used in combination with "-g").

**-l** [length of tripcodes] : Specify either 10 or 12. (Please note that 12 character tripcodes is only available at 2ch.net).

**-x** [number of blocks/SM] : Specify the number of blocks per SM (1 <= n <= 256) for CUDA devices.

**-t** [number of threads] : Specify number of CPU search threads.

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
* [Meriken's Tripcode Engine English No. 6 (5/14/2016)]( https://archive.rebeccablacktech.com/g/thread/54553624 )
* [Meriken's Tripcode Engine No. 7 (5/20/2016)]( https://archive.rebeccablacktech.com/g/thread/54662329 )
* [Meriken's Tripcode Engine No. 8 (5/21/2016)]( https://archive.rebeccablacktech.com/g/thread/54679797 )
* [Meriken's Tripcode Engine No. 9 (5/29/2016)]( https://archive.rebeccablacktech.com/g/thread/54807160 )
* [Meriken's Tripcode Engine No. 10 (6/4/2016)]( https://archive.rebeccablacktech.com/g/thread/54906403 )

## Miscellaneous Notes

Author: [meriken.ygch.net@gmail.com]( mailto:meriken.ygch.net@gmail.com )

Merriken Trip Code Engine は、2ch.net などの画像掲示板ユーザーを対象とした、グラフィカル ユーザー ベースのネットワーク互換性のあるエンジンです。これは、[Web]( http://tripcode.ygch.net/yggdrasil/ ) ベースの分散型トリップ コード生成サービスです。[TripCodes]( http://meriken.ygch.net/programming/merikens-tripcode-generator/ )...

Copyright © 2016 ◆/Meriken/.
