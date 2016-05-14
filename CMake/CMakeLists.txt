cmake_minimum_required(VERSION 2.8.4)
project(MerikensTripcodeEngine CXX)

set(MTE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../SourceFiles)
set(MTE_BOOST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../BoostPackages)
set(MTE_BOOST_PACKAGE "boost_1_61_0")


###########
# OPTIONS #
###########

option(USE_YASM "USE_YASM" ON)
option(ENABLE_OPENCL "ENABLE_OPENCL" ON)
option(ENGLISH_VERSION "ENGLISH_VERSION" ON)

if (CMAKE_COMPILER_IS_GNUCXX)
	execute_process(COMMAND ${CMAKE_CXX_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
	if (NOT (GCC_VERSION VERSION_GREATER 5.0 OR GCC_VERSION VERSION_EQUAL 5.0))
		message(FATAL_ERROR "g++ 5.0 or later is required.")
		quit()
	endif()
endif()



##########
# OpenCL #
##########

file(COPY "${MTE_SOURCE_DIR}/OpenCL" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
set(CYGWIN_AMD_APP_SDK_DIR "/cygdrive/c/Program\ Files\ (x86)/AMD\ APP\ SDK/3.0")
if(AMDAPPSDKROOT AND EXISTS ${AMDAPPSDKROOT})
	set(UNIX_AMD_APP_SDK_DIR ${AMDAPPSDKROOT})
else()
	set(UNIX_AMD_APP_SDK_DIR "/opt/AMDAPPSDK-3.0")
endif()
if(ENABLE_OPENCL AND CYGWIN AND EXISTS ${CYGWIN_AMD_APP_SDK_DIR})
    set(OPENCL_LINK_LIBRARIES
        OpenCL)
    set(OPENCL_INCLUDE_DIR
        "${CYGWIN_AMD_APP_SDK_DIR}/include")
    set(OPENCL_LINK_DIR
        "${CYGWIN_AMD_APP_SDK_DIR}/lib/x86_64")
elseif(ENABLE_OPENCL AND UNIX AND EXISTS ${UNIX_AMD_APP_SDK_DIR})
    set(OPENCL_LINK_LIBRARIES
        OpenCL)
    set(OPENCL_INCLUDE_DIR
        "${UNIX_AMD_APP_SDK_DIR}/include")
    set(OPENCL_LINK_DIR
        "${UNIX_AMD_APP_SDK_DIR}/lib/x86_64")
else()
    set(ENABLE_OPENCL FALSE)
endif()
if(ENABLE_OPENCL)
    file(GLOB OPENCL_SOURCES
        "${MTE_SOURCE_DIR}/OpenCL*.cpp")
    set(MTE_COMPILE_FLAGS ${MTE_COMPILE_FLAGS}
        -DENABLE_OPENCL)
endif()



set(YASM_FILES)
find_program(YASM_EXE NAMES yasm)
if((UNIX AND NOT CYGWIN) OR (NOT YASM_EXE))
    set(USE_YASM FALSE)
endif()
if(USE_YASM)
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DUSE_YASM")
    function(assemble_yasm_files out_var)
	set(result)
	foreach(in_f ${ARGN})
		set(out_f "${CMAKE_CURRENT_BINARY_DIR}/${in_f}")
		string(REPLACE ".asm" ".o" out_f ${out_f})
		set(in_f "${MTE_SOURCE_DIR}/${in_f}")
		add_custom_command(
			OUTPUT ${out_f}
			DEPENDS ${in_f}
			COMMAND ${YASM_EXE}
			ARGS -f Win64 -o ${out_f} ${in_f}
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      			COMMENT "Building YASM object ${out_f}")
		list(APPEND result ${out_f})
	endforeach()
	set(${out_var} "${result}" PARENT_SCOPE)
    endfunction()
    assemble_yasm_files(YASM_FILES
	CPU10_x64_AVX.asm
	CPU10_x64_AVX2.asm
	CPU10_x64_SSE2.asm
	CPU10_x64_SSE2_Nehalem.asm
	CPU12_x64_AVX.asm
	CPU12_x64_AVX2.asm
	CPU12_x64_SSE2.asm
	CPU12_x64_SSE2_Nehalem.asm)
endif()



set(CORE_SOURCES
	${MTE_SOURCE_DIR}/Main.cpp
	${MTE_SOURCE_DIR}/Patterns.cpp
	${MTE_SOURCE_DIR}/Testing.cpp
	${MTE_SOURCE_DIR}/Verification10.cpp
	${MTE_SOURCE_DIR}/Verification12.cpp
	${MTE_SOURCE_DIR}/VerificationDuplicates.cpp
	${MTE_SOURCE_DIR}/UtilityFunctions.cpp)
if (USE_YASM)
	file(GLOB CPU_SOURCES
		"${MTE_SOURCE_DIR}/CPU10_yasm.cpp"
		"${MTE_SOURCE_DIR}/CPU10_AVX2.cpp"
		"${MTE_SOURCE_DIR}/CPU12_yasm.cpp")
else()
	file(GLOB CPU_SOURCES
		"${MTE_SOURCE_DIR}/CPU10_SSE2Intrinsics.cpp"
		"${MTE_SOURCE_DIR}/CPU12_SSE2Intrinsics.cpp")
endif()
set(SOURCES
	${CORE_SOURCES}
	${CPU_SOURCES}
	${OPENCL_SOURCES})



LINK_LIBRARIES(${OPENCL_LINK_LIBRARIES} boost_system boost_iostreams)
include_directories(
    "${MTE_SOURCE_DIR}"
    "${MTE_BOOST_DIR}/include"
    "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/"
    ${OPENCL_INCLUDE_DIR})
link_directories(
    "${MTE_BOOST_DIR}/lib/Cygwin64"
    "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/stage/lib/"
    ${OPENCL_LINK_DIR})



if(UNIX AND NOT CYGWIN)
    SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -pthread")
endif()
if(CYGWIN)
    SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -fno-access-control")
endif(CYGWIN)
SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -std=c++11 -Wall -Wno-deprecated-declarations -O3")
if(ENGLISH_VERSION)
	set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DENGLISH_VERSION")
endif()
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS} ${MTE_COMPILE_FLAGS}")
#SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} --enable-auto-import" )

#set(CMAKE_INCLUDE_CURRENT_DIR ON)
add_executable(MerikensTripcodeEngine ${SOURCES} ${YASM_FILES})
set_target_properties(MerikensTripcodeEngine PROPERTIES LINKER_LANGUAGE CXX)
#set(CMAKE_CXX_LINK_EXECUTABLE "<CMAKE_CXX_COMPILER> <FLAGS> <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

install_programs(/bin FILES ${CMAKE_CURRENT_BINARY_DIR}/MerikensTripcodeEngine)
file(GLOB GCN_SOURCE_FILES "${MTE_SOURCE_DIR}/OpenCL/bin/*.asm")
install(FILES ${GCN_SOURCE_FILES} DESTINATION etc/MerikensTripcodeEngine/OpenCL/bin)
file(GLOB OPENCL_SOURCE_FILES "${MTE_SOURCE_DIR}/OpenCL/*.cl")
install(FILES ${OPENCL_SOURCE_FILES} DESTINATION etc/MerikensTripcodeEngine/OpenCL)
