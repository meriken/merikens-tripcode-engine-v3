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
./bootstrap.sh 
./b2 link=static runtime-link=static -j 8
cd ../../

mkdir CMakeBuild/
cd CMakeBuild/
cmake ../SourceFiles/
make
echo TEST/ >> patterns.txt
