#!/bin/sh
set -e

# CLRadeonExtender
cd CLRadeonExtender/
echo Extracting CLRadeonExtender-*.zip...
7z x -y CLRadeonExtender-*.zip > /dev/null
cd CLRX-mirror-master/
mkdir -p build/
cd build/
cmake ../
make
cd ../../../

# Boost
cd BoostPackages/
echo Extracting boost_1_61_0.7z...
7z x -y boost_1_61_0.7z > /dev/null
cp sp_counted_base_gcc_x86.hpp boost_1_61_0/boost/smart_ptr/detail
cd boost_1_61_0
find boost -type f -exec sed -i '/pragma.*deprecated/d' {} \;
./bootstrap.sh --with-toolset=gcc
# ./b2 toolset=gcc link=static runtime-link=static -j 8 # FreeBSD is not happy.
./b2 toolset=gcc link=static -j 8
cd ../../

mkdir -p CMakeBuild/
cd CMakeBuild/
cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ ../SourceFiles/
make

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
