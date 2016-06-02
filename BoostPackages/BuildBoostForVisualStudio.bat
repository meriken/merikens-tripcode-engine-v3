cd boost_1_61_0
cmd /c ".\bootstrap.bat"
.\b2 link=static runtime-link=static address-model=32 toolset=msvc-14.0 -j 8 --stagedir=stage/Win32 --with-system --with-iostreams --with-filesystem --with-locale
.\b2 link=static runtime-link=static address-model=64 toolset=msvc-14.0 -j 8 --stagedir=stage/x64 --with-system --with-iostreams --with-filesystem --with-locale
