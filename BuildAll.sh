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
if [ -f ./b2 ]; then
	# ./b2 link=static runtime-link=static -j 8 # FreeBSD is not happy.
	./b2 link=static -j 8
else
    # bootstrap.sh cannot automatically detect clang on FreeBSD.
	./bootstrap.sh --with-toolset=clang
	# ./b2 toolset=clang link=static runtime-link=static -j 8 # FreeBSD is not happy.
	./b2 toolset=clang link=static -j 8
fi
cd ../../

mkdir CMakeBuild/
cd CMakeBuild/
cmake ../SourceFiles/
make
echo TEST/ >> patterns.txt
