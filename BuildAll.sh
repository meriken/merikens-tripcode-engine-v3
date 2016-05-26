#!/bin/sh
set -e

# Options
CMAKE_VERSION="3.5.2"
BOOTSTRAP_OPTIONS=""
B2_OPTIONS=""
CMAKE_OPTIONS=""
MAKE_OPTIONS=""
RUN_TESTS=false
NUM_THREADS="8"
INSTALL=false
while [ "$#" -gt 0 ]; do
key="$1"
case $key in
    --with-toolset=gcc)
	BOOTSTRAP_OPTIONS="$BOOTSTRAP_OPTIONS --with-toolset=gcc"
	B2_OPTIONS="$B2_OPTIONS toolset=gcc"
	CMAKE_OPTIONS="$CMAKE_OPTIONS -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++"
    ;;
    --with-toolset=clang)
	BOOTSTRAP_OPTIONS="$BOOTSTRAP_OPTIONS --with-toolset=clang"
	B2_OPTIONS="$B2_OPTIONS toolset=clang cxxflags=-stdlib=libc++"
	CMAKE_OPTIONS=$'$CMAKE_OPTIONS -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_FLAGS=-stdlib=libc++'
    ;;
    --enable-cuda)
	CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_CUDA=ON"
    ;;
    --disable-cuda)
	CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_CUDA=OFF"
    ;;
    --enable-opencl)
	CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_OPENCL=ON"
    ;;
    --disable-opencl)
	CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_OPENCL=OFF"
    ;;
    --enable-cuda-des-multiple-kernels-mode)
	CMAKE_OPTIONS="$CMAKE_OPTIONS -DENABLE_CUDA_DES_MULTIPLE_KERNELS_MODE=ON"
    ;;
    --english-version)
	CMAKE_OPTIONS="$CMAKE_OPTIONS -DENGLISH_VERSION=ON"
    ;;
    --japanese-version)
	CMAKE_OPTIONS="$CMAKE_OPTIONS -DENGLISH_VERSION=OFF"
    ;;
    --run-tests)
	RUN_TESTS=true
    ;;
    --install)
	INSTALL=true
    ;;
    --rebuild)
	rm -rf CMake/cmake-$CMAKE_VERSION CLRadeonExtender/CLRX-mirror-master/build BoostPackages/boost_1_61_0 CMakeBuild/
    ;;
    -j)
	NUM_THREADS="$2"
	shift
    ;;
   	*)
	echo "Unknown option: $key"
	exit 1
    ;;
esac
shift
done
MAKE_OPTIONS="$MAKE_OPTIONS -j $NUM_THREADS"
B2_OPTIONS="$B2_OPTIONS -j $NUM_THREADS"
if [ -f "/etc/arch-release" ]; then
    CMAKE_OPTIONS="$CMAKE_OPTIONS -DLIB_INSTALL_DIR=lib"
fi

# CMake
BUILD_CMAKE=false
CMAKE="cmake"
if ! cmake --version > /dev/null
then
    BUILD_CMAKE=true
fi
if [ "$BUILD_CMAKE" = false ]
then
    INSTALLED_CMAKE_VERSION=`cmake --version | sed 's/^[^0-9][^0-9]*//g' | awk '1 { print $1; }'`
    RESULT=$(echo $CMAKE_VERSION $INSTALLED_CMAKE_VERSION | awk '{ split($1, a, "."); split($2, b, ".");for (i = 1; i <= 4; i++) if (a[i] < b[i]) { x =-1; break; } else if (a[i] > b[i]) { x = 1; break; } print x; }')
    if  [ "$RESULT" = "1" ]
    then
	BUILD_CMAKE=true
    fi
fi
if [ "$BUILD_CMAKE" = true ]
then
    BUILD_CMAKE=true
    CMAKE="`pwd`/CMake/cmake-$CMAKE_VERSION/bin/cmake"
    if [ ! -f $CMAKE ]
    then
        cd CMake
        rm -rf cmake-$CMAKE_VERSION
        tar xzf cmake-$CMAKE_VERSION.tar.gz
        cd cmake-$CMAKE_VERSION
        ./configure
        make $MAKE_OPTIONS
        cd ../..
    fi
fi

# CLRadeonExtender
if [ ! -f "./CLRadeonExtender/CLRX-mirror-master/build/programs/clrxasm"]
then
    cd CLRadeonExtender/
    echo Extracting CLRadeonExtender...
    7z x -y CLRadeonExtender-*.zip > /dev/null
    cd CLRX-mirror-master/
    mkdir -p build/
    cd build/
    $CMAKE $CMAKE_OPTIONS -DCMAKE_INSTALL_PREFIX=/usr ../
    make $MAKE_OPTIONS
    cd ../../../
fi

# Boost
string="$CPLUS_INCLUDE_PATH"
substring="/usr/include/python2.7"
if [ -d substring ] && test "${string#*$substring}" == "$string"
then
    export CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:$substring"
fi
cd BoostPackages/
echo Extracting boost_1_61_0.7z...
7z x -y boost_1_61_0.7z > /dev/null
cp sp_counted_base_gcc_x86.hpp boost_1_61_0/boost/smart_ptr/detail
cd boost_1_61_0
OS="`uname`"
case $OS in
  'FreeBSD' | 'Darwin')
    find boost -type f -exec sed -i '.original' '/pragma.*deprecated/d' {} \;
    ;;
  *) 
    find boost -type f -exec sed -i '/pragma.*deprecated/d' {} \;
    ;;
esac
./bootstrap.sh $BOOTSTRAP_OPTIONS
case $OS in
  'FreeBSD')
    ./b2 $B2_OPTIONS link=static variant=release --with-iostreams --with-system
    ;;
  *) 
    ./b2 $B2_OPTIONS runtime-link=static link=static variant=release --with-iostreams --with-system
    ;;
esac

cd ../../

mkdir -p CMakeBuild/
cd CMakeBuild/
$CMAKE $CMAKE_OPTIONS -DCMAKE_INSTALL_PREFIX=/usr ../SourceFiles/
make $MAKE_OPTIONS

if [ "$RUN_TESTS" = true ]
then
	echo "#regex" > patterns.txt
	echo "^TEST." >> patterns.txt
	echo Testing MerikensTripcodeEngine...
	if ! ./MerikensTripcodeEngine -l 10 -u 60 > /dev/null
	then
		echo >&2 \"MerikensTripcodeEngine -l 10\" failed.
		exit 1
	fi
	if ! ./MerikensTripcodeEngine -l 12 -u 60 > /dev/null
	then
		echo >&2 \"MerikensTripcodeEngine -l 12\" failed.
		exit 1
	fi
	echo Tests were successful.
fi

cd ../

if [ "$INSTALL" = true ]
then
    echo Installing CLRadeonExtender...
    sudo make -C CLRadeonExtender/CLRX-mirror-master/build install
    echo Installing MerikensTripcodeEngine...
    sudo make -C CMakeBuild install
fi

