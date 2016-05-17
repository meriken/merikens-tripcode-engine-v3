cmake_minimum_required(VERSION 2.8.4)
project(MerikensTripcodeEngine C CXX)

set(MTE_BOOST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../BoostPackages)
set(MTE_BOOST_PACKAGE "boost_1_61_0")



###########
# OPTIONS #
###########

option(USE_YASM "USE_YASM" ON)
option(ENABLE_OPENCL "ENABLE_OPENCL" ON)
option(ENABLE_CUDA "ENABLE_CUDA" ON)
option(ENGLISH_VERSION "ENGLISH_VERSION" ON)
option(ENABLE_CUDA_DES_MULTIPLE_KERNELS_MODE "ENABLE_CUDA_DES_MULTIPLE_KERNELS_MODE" OFF)

if(ENGLISH_VERSION)
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DENGLISH_VERSION")
endif()
if(ENABLE_CUDA_DES_MULTIPLE_KERNELS_MODE)
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DCUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE")
endif()



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
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DARCH_64BIT")
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
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DARCH_X86")
else()
    set(ARCH_X86 FALSE)
endif()
if (ARCH_X86)
    message(STATUS "ARCH_X86 = TRUE")
else()
    message(STATUS "ARCH_X86 = FALSE")
endif()    



##########
# OPENCL #
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
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DENABLE_OPENCL")
endif()



########
# YASM #
########

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



##################
# CUDA DETECTION #
##################

set(UNIX_NVIDIA_CUDA_SDK_DIR "/usr/local/cuda-7.5")
if(ARCH_64BIT AND ENABLE_CUDA AND UNIX AND EXISTS ${UNIX_NVIDIA_CUDA_SDK_DIR})
    set(CUDA_LINK_LIBRARIES cudart)
    set(CUDA_INCLUDE_DIR "${UNIX_NVIDIA_CUDA_SDK_DIR}/include")
    set(CUDA_LINK_DIR "${UNIX_NVIDIA_CUDA_SDK_DIR}/lib64")
else()
    set(ENABLE_CUDA FALSE)
endif()
if(ENABLE_CUDA)
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DENABLE_CUDA")
endif()


if(UNIX AND NOT CYGWIN)
    SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -pthread")
endif()
if(CYGWIN)
    SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -fno-access-control")
endif(CYGWIN)
SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -std=c++11 -Wall -Wno-deprecated-declarations -O3")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS} ${MTE_COMPILE_FLAGS}")
#SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} --enable-auto-import" )



########
# CUDA #
########

if(ENABLE_CUDA AND NOT ENABLE_CUDA_DES_MULTIPLE_KERNELS_MODE)
 	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/CUDA10_Registers.cu.o
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers.cu
		COMMAND nvcc
		ARGS -DENABLE_CUDA -std=c++11 -gencode=arch=compute_50,code=sm_50 -gencode=arch=compute_52,code=sm_52 -gencode=arch=compute_53,code=sm_53 -gencode=arch=compute_53,code=compute_53 -I"${CUDA_INCLUDE_DIR}" -I"${MTE_BOOST_DIR}/include" -I"${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/" --keep-dir "${CMAKE_CURRENT_BINARY_DIR}" -maxrregcount=168 --ptxas-options=-v --machine 64 --compile -cudart static -Xcompiler "${CMAKE_CXX_FLAGS}" -o "${CMAKE_CURRENT_BINARY_DIR}/CUDA10_Registers.cu.o" "${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers.cu"
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Building CUDA object CUDA10_Registers.cu.o")
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/CUDA10_SharedMemory.cu.o
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_SharedMemory.cu
		COMMAND nvcc
		ARGS -DENABLE_CUDA -std=c++11 -gencode=arch=compute_20,code=sm_20 -gencode=arch=compute_20,code=sm_21 -gencode=arch=compute_30,code=sm_30 -gencode=arch=compute_32,code=sm_32 -gencode=arch=compute_35,code=sm_35 -gencode=arch=compute_37,code=sm_37 -I"${CUDA_INCLUDE_DIR}" -I"${MTE_BOOST_DIR}/include" -I"${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/" --keep-dir "${CMAKE_CURRENT_BINARY_DIR}" -maxrregcount=42 --ptxas-options=-v --machine 64 --compile -cudart static -Xcompiler "${CMAKE_CXX_FLAGS}" -o "${CMAKE_CURRENT_BINARY_DIR}/CUDA10_SharedMemory.cu.o" "${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_SharedMemory.cu"
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Building CUDA object CUDA10_SharedMemory.cu.o")
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/CUDA12.cu.o
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/CUDA12.cu
		COMMAND nvcc
		ARGS -DENABLE_CUDA -std=c++11 -gencode=arch=compute_20,code=sm_20 -gencode=arch=compute_20,code=sm_21 -gencode=arch=compute_30,code=sm_30 -gencode=arch=compute_32,code=sm_32 -gencode=arch=compute_35,code=sm_35 -gencode=arch=compute_37,code=sm_37 -gencode=arch=compute_50,code=sm_50 -gencode=arch=compute_52,code=sm_52 -gencode=arch=compute_53,code=sm_53 -gencode=arch=compute_53,code=compute_53 -I"${CUDA_INCLUDE_DIR}" -I"${MTE_BOOST_DIR}/include" -I"${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/" --keep-dir "${CMAKE_CURRENT_BINARY_DIR}" -maxrregcount=0 --ptxas-options=-v --machine 64 --compile -cudart static -Xcompiler "${CMAKE_CXX_FLAGS}" -o "${CMAKE_CURRENT_BINARY_DIR}/CUDA12.cu.o" "${CMAKE_CURRENT_SOURCE_DIR}/CUDA12.cu"
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Building CUDA object CUDA12.cu.o")

elseif(ENABLE_CUDA AND ENABLE_CUDA_DES_MULTIPLE_KERNELS_MODE)
 	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/CUDA10_Registers.cu.o
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers.cu
		COMMAND nvcc
		ARGS -DCUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE  -DENABLE_CUDA -std=c++11 -gencode=arch=compute_50,code=sm_50 -gencode=arch=compute_52,code=sm_52 -gencode=arch=compute_53,code=sm_53 -gencode=arch=compute_53,code=compute_53 -I"${CUDA_INCLUDE_DIR}" -I"${MTE_BOOST_DIR}/include" -I"${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/" --keep-dir "${CMAKE_CURRENT_BINARY_DIR}" -maxrregcount=168 --ptxas-options=-v --machine 64 --compile -cudart static -Xcompiler "${CMAKE_CXX_FLAGS}" -o "${CMAKE_CURRENT_BINARY_DIR}/CUDA10_Registers.cu.o" "${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers.cu"
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Building CUDA object CUDA10_Registers.cu.o")
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/CUDA10_SharedMemory.cu.o
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_SharedMemory.cu
		COMMAND nvcc
		ARGS -DCUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE  -DENABLE_CUDA -std=c++11 -gencode=arch=compute_20,code=sm_20 -gencode=arch=compute_20,code=sm_21 -gencode=arch=compute_30,code=sm_30 -gencode=arch=compute_32,code=sm_32 -gencode=arch=compute_35,code=sm_35 -gencode=arch=compute_37,code=sm_37 -I"${CUDA_INCLUDE_DIR}" -I"${MTE_BOOST_DIR}/include" -I"${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/" --keep-dir "${CMAKE_CURRENT_BINARY_DIR}" -maxrregcount=42 --ptxas-options=-v --machine 64 --compile -cudart static -Xcompiler "${CMAKE_CXX_FLAGS}" -o "${CMAKE_CURRENT_BINARY_DIR}/CUDA10_SharedMemory.cu.o" "${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_SharedMemory.cu"
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Building CUDA object CUDA10_SharedMemory.cu.o")
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/CUDA12.cu.o
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/CUDA12.cu
		COMMAND nvcc
		ARGS -DCUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE  -DENABLE_CUDA -std=c++11 -gencode=arch=compute_20,code=sm_20 -gencode=arch=compute_20,code=sm_21 -gencode=arch=compute_30,code=sm_30 -gencode=arch=compute_32,code=sm_32 -gencode=arch=compute_35,code=sm_35 -gencode=arch=compute_37,code=sm_37 -gencode=arch=compute_50,code=sm_50 -gencode=arch=compute_52,code=sm_52 -gencode=arch=compute_53,code=sm_53 -gencode=arch=compute_53,code=compute_53 -I"${CUDA_INCLUDE_DIR}" -I"${MTE_BOOST_DIR}/include" -I"${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/" --keep-dir "${CMAKE_CURRENT_BINARY_DIR}" -maxrregcount=0 --ptxas-options=-v --machine 64 --compile -cudart static -Xcompiler "${CMAKE_CXX_FLAGS}" -o "${CMAKE_CURRENT_BINARY_DIR}/CUDA12.cu.o" "${CMAKE_CURRENT_SOURCE_DIR}/CUDA12.cu"
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Building CUDA object CUDA12.cu.o")
 
    function(compile_cuda_des_multiple_kernels_files out_var)
        set(result)
        foreach(in_f ${ARGN})
	        set(out_f "${CMAKE_CURRENT_BINARY_DIR}/${in_f}")
	        string(REPLACE ".cu" ".cu.o" out_f ${out_f})
	        set(in_f "${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/${in_f}")
	        add_custom_command(
		        OUTPUT ${out_f}
		        DEPENDS ${in_f}
		        COMMAND nvcc
	            ARGS -DCUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE -DENABLE_CUDA -std=c++11 -gencode=arch=compute_50,code=sm_50 -gencode=arch=compute_52,code=sm_52 -gencode=arch=compute_53,code=sm_53 -I"${CMAKE_CURRENT_SOURCE_DIR}" -I"${CUDA_INCLUDE_DIR}" -I"${MTE_BOOST_DIR}/include" -I"${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/" --keep-dir "${CMAKE_CURRENT_BINARY_DIR}" -maxrregcount=168 --machine 64 --compile -cudart static -Xcompiler "${CMAKE_CXX_FLAGS}" -o ${out_f} ${in_f}
		        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
          		COMMENT "Building CUDA object ${out_f}")
	        list(APPEND result ${out_f})
        endforeach()
        set(${out_var} "${result}" PARENT_SCOPE)
    endfunction()
    compile_cuda_des_multiple_kernels_files(CUDA_DES_MULTIPLE_KERNELS_FILES
        CUDA10_Registers_KernelLauncher0.cu 
        CUDA10_Registers_KernelLauncher1.cu 
        CUDA10_Registers_KernelLauncher2.cu 
        CUDA10_Registers_KernelLauncher3.cu 
        CUDA10_Registers_KernelLauncher4.cu 
        CUDA10_Registers_KernelLauncher5.cu 
        CUDA10_Registers_KernelLauncher6.cu 
        CUDA10_Registers_KernelLauncher7.cu 
        CUDA10_Registers_KernelLauncher8.cu 
        CUDA10_Registers_KernelLauncher9.cu 
        CUDA10_Registers_KernelLauncher10.cu 
        CUDA10_Registers_KernelLauncher11.cu 
        CUDA10_Registers_KernelLauncher12.cu 
        CUDA10_Registers_KernelLauncher13.cu 
        CUDA10_Registers_KernelLauncher14.cu 
        CUDA10_Registers_KernelLauncher15.cu)
endif()

if(ENABLE_CUDA)
    set(CUDA_FILES
        ${CMAKE_CURRENT_BINARY_DIR}/CUDA10_Registers.cu.o
        ${CMAKE_CURRENT_BINARY_DIR}/CUDA10_SharedMemory.cu.o
        ${CMAKE_CURRENT_BINARY_DIR}/CUDA12.cu.o
        ${CUDA_DES_MULTIPLE_KERNELS_FILES})
endif()



LINK_LIBRARIES(${OPENCL_LINK_LIBRARIES} ${CUDA_LINK_LIBRARIES} boost_system boost_iostreams)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${MTE_BOOST_DIR}/include"
    "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/"
    ${OPENCL_INCLUDE_DIR}
    ${CUDA_INCLUDE_DIR})
link_directories(
    "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/stage/lib/"
    ${OPENCL_LINK_DIR}
    ${CUDA_LINK_DIR})



#set(CMAKE_INCLUDE_CURRENT_DIR ON)
add_executable(MerikensTripcodeEngine ${SOURCES} ${YASM_FILES} ${CUDA_FILES})
set_target_properties(MerikensTripcodeEngine PROPERTIES LINKER_LANGUAGE CXX)
#set(CMAKE_CXX_LINK_EXECUTABLE "<CMAKE_CXX_COMPILER> <FLAGS> <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

install_programs(/bin FILES ${CMAKE_CURRENT_BINARY_DIR}/MerikensTripcodeEngine)
file(GLOB GCN_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL/bin/*.asm")
install(FILES ${GCN_SOURCE_FILES} DESTINATION etc/MerikensTripcodeEngine/OpenCL/bin)
file(GLOB OPENCL_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL/*.cl")
install(FILES ${OPENCL_SOURCE_FILES} DESTINATION etc/MerikensTripcodeEngine/OpenCL)

