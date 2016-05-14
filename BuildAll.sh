#!/bin/sh

cd CLRadeonExtender/
7z x -y CLRadeonExtender-*.zip 
cd CLRX-mirror-master/
mkdir build/
cd build/
cmake ../
make
cd ../../../

cd BoostPackages/
7z x -y boost_1_61_0.7z
cd boost_1_61_0
./bootstrap.sh 
./b2 link=static runtime-link=static -j 8
cd ../../

mkdir CMakeBuild/
cd CMakeBuild/
cmake ../CMake/
make
echo TEST/ >> patterns.txt
