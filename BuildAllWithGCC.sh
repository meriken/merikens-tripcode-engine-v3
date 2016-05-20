#!/bin/sh

# CLRadeonExtender
cd CLRadeonExtender/
7z x -y CLRadeonExtender-*.zip 
cd CLRX-mirror-master/
mkdir build/
cd build/
cmake ../
make
cd ../../../

# Boost
cd BoostPackages/
7z x -y boost_1_61_0.7z
cd boost_1_61_0
./bootstrap.sh --with-toolset=gcc
./b2 toolset=gcc link=static runtime-link=static -j 8
cd ../../

mkdir CMakeBuild/
cd CMakeBuild/
cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ ../SourceFiles/
make
echo TEST/ >> patterns.txt
