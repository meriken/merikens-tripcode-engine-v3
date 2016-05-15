cmake_minimum_required(VERSION 2.8.4)
project(MerikensTripcodeEngine C CXX)

set(MTE_BOOST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../BoostPackages)
set(MTE_BOOST_PACKAGE "boost_1_61_0")


###########
# OPTIONS #
###########

option(USE_YASM "USE_YASM" ON)
option(ENABLE_OPENCL "ENABLE_OPENCL" ON)
option(ENGLISH_VERSION "ENGLISH_VERSION" ON)



##########################
# ARCHITECTURE DETECTION #
##########################

include(CheckTypeSize) 
check_type_size("void*" SIZEOF_VOID_P BUILTIN_TYPES_ONLY) 
configure_file(config.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/config.hpp" @ONLY)
string(REGEX REPLACE "^[ \t]*#define[ \t]+SIZEOF_VOID_P[ \t]+" "" SIZEOF_VOID_P_VALUE ${SIZEOF_VOID_P_CODE})
string(REGEX REPLACE "[^0-9].*$" "" SIZEOF_VOID_P_VALUE "${SIZEOF_VOID_P_VALUE}")
if (SIZEOF_VOID_P_VALUE STREQUAL "8")
    set(ARCH_64BIT TRUE)
    set(MTE_COMPILE_FLAGS ${MTE_COMPILE_FLAGS} -DARCH_64BIT)
else()
    set(ARCH_64BIT FALSE)
endif()
if (ARCH_64BIT)
    message(STATUS "ARCH_64BIT = TRUE")
else()
    message(STATUS "ARCH_64BIT = FALSE")
endif()    

try_run(
    RUN_RESULT
    COMPILE_RESULT
    "${CMAKE_BINARY_DIR}"
    "${CMAKE_SOURCE_DIR}/DetectX86.cpp"
    COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT)
if (COMPILE_OUTPUT MATCHES "ARCH_X86")
    set(ARCH_X86 TRUE)
    set(MTE_COMPILE_FLAGS ${MTE_COMPILE_FLAGS} -DARCH_X86)
else()
    set(ARCH_X86 FALSE)
endif()
if (ARCH_X86)
    message(STATUS "ARCH_X86 = TRUE")
else()
    message(STATUS "ARCH_X86 = FALSE")
endif()    



##########
# OpenCL #
##########

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
set(CYGWIN_AMD_APP_SDK_DIR "/cygdrive/c/Program\ Files\ (x86)/AMD\ APP\ SDK/3.0")
if(AMDAPPSDKROOT AND EXISTS ${AMDAPPSDKROOT})
	set(UNIX_AMD_APP_SDK_DIR ${AMDAPPSDKROOT})
else()
	set(UNIX_AMD_APP_SDK_DIR "/opt/AMDAPPSDK-3.0")
endif()
set(UNIX_NVIDIA_OPENCL_SDK_DIR "/usr/local/cuda-7.5")
if(ARCH_X86 AND ENABLE_OPENCL AND CYGWIN AND EXISTS ${CYGWIN_AMD_APP_SDK_DIR})
    set(OPENCL_LINK_LIBRARIES OpenCL)
    set(OPENCL_INCLUDE_DIR "${CYGWIN_AMD_APP_SDK_DIR}/include")
    if (ARCH_64BIT)
        set(OPENCL_LINK_DIR "${CYGWIN_AMD_APP_SDK_DIR}/lib/x86_64")
    else()
        set(OPENCL_LINK_DIR "${CYGWIN_AMD_APP_SDK_DIR}/lib/x86")
    endif()
elseif(ARCH_64BIT AND ENABLE_OPENCL AND UNIX AND EXISTS ${UNIX_NVIDIA_OPENCL_SDK_DIR})
    set(OPENCL_LINK_LIBRARIES OpenCL)
    set(OPENCL_INCLUDE_DIR "${UNIX_NVIDIA_OPENCL_SDK_DIR}/include")
    set(OPENCL_LINK_DIR "${UNIX_NVIDIA_OPENCL_SDK_DIR}/lib64")
elseif(ARCH_X86 AND ENABLE_OPENCL AND UNIX AND EXISTS ${UNIX_AMD_APP_SDK_DIR})
    set(OPENCL_LINK_LIBRARIES OpenCL)
    set(OPENCL_INCLUDE_DIR "${UNIX_AMD_APP_SDK_DIR}/include")
    if (ARCH_64BIT)
        set(OPENCL_LINK_DIR "${UNIX_AMD_APP_SDK_DIR}/lib/x86_64")
    else()
        set(OPENCL_LINK_DIR "${UNIX_AMD_APP_SDK_DIR}/lib/x86")
    endif()
else()
    set(ENABLE_OPENCL FALSE)
endif()
if(ENABLE_OPENCL)
    file(GLOB OPENCL_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL*.cpp")
    set(MTE_COMPILE_FLAGS ${MTE_COMPILE_FLAGS} -DENABLE_OPENCL)
endif()



set(YASM_FILES)
find_program(YASM_EXE NAMES yasm)
if((UNIX AND NOT CYGWIN) OR (NOT YASM_EXE) OR (NOT ARCH_X86))
    set(USE_YASM FALSE)
endif()
if(USE_YASM)
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DUSE_YASM")
    function(assemble_yasm_files out_var)
	set(result)
	foreach(in_f ${ARGN})
		set(out_f "${CMAKE_CURRENT_BINARY_DIR}/${in_f}")
		string(REPLACE ".asm" ".o" out_f ${out_f})
		set(in_f "${CMAKE_CURRENT_SOURCE_DIR}/${in_f}")
		if (ARCH_64BIT)
		    set(YASM_FORMAT "Win64")
		else()
		    set(YASM_FORMAT "Win32")
		endif()
		add_custom_command(
			OUTPUT ${out_f}
			DEPENDS ${in_f}
			COMMAND ${YASM_EXE}
			ARGS -f ${YASM_FORMAT} -o ${out_f} ${in_f}
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      			COMMENT "Building YASM object ${out_f}")
		list(APPEND result ${out_f})
	endforeach()
	set(${out_var} "${result}" PARENT_SCOPE)
    endfunction()
    if (ARCH_64BIT)
        assemble_yasm_files(YASM_FILES
	    CPU10_x64_AVX.asm
	    CPU10_x64_AVX2.asm
	    CPU10_x64_SSE2.asm
	    CPU10_x64_SSE2_Nehalem.asm
	    CPU12_x64_AVX.asm
	    CPU12_x64_AVX2.asm
	    CPU12_x64_SSE2.asm
	    CPU12_x64_SSE2_Nehalem.asm)
    else()
        assemble_yasm_files(YASM_FILES
	    CPU10_x86_AVX.asm
	    CPU10_x86_AVX2.asm
	    CPU10_x86_SSE2.asm
	    CPU10_x86_SSE2_Nehalem.asm
	    CPU12_x86_AVX.asm
	    CPU12_x86_AVX2.asm
	    CPU12_x86_SSE2.asm
	    CPU12_x86_SSE2_Nehalem.asm)
    endif()
endif()



set(CORE_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/Main.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/Patterns.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/Testing.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/Verification10.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/Verification12.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/VerificationDuplicates.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/UtilityFunctions.cpp)
if (USE_YASM)
	file(GLOB CPU_SOURCES
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU10_yasm.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU10_AVX2.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU12_yasm.cpp")
else()
	file(GLOB CPU_SOURCES
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU10_SSE2Intrinsics.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU12_SSE2Intrinsics.cpp")
endif()
set(SOURCES
	${CORE_SOURCES}
	${CPU_SOURCES}
	${OPENCL_SOURCES})



LINK_LIBRARIES(${OPENCL_LINK_LIBRARIES} boost_system boost_iostreams)
include_directories(
    "${CMAKE_CURRENT_SOURCE_DIR}"
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
file(GLOB GCN_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL/bin/*.asm")
install(FILES ${GCN_SOURCE_FILES} DESTINATION etc/MerikensTripcodeEngine/OpenCL/bin)
file(GLOB OPENCL_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL/*.cl")
install(FILES ${OPENCL_SOURCE_FILES} DESTINATION etc/MerikensTripcodeEngine/OpenCL)
