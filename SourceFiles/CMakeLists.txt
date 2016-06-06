cmake_minimum_required(VERSION 3.1)
project(MerikensTripcodeEngine CXX C)

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
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DCUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE=0")
endif()



##########################
# ARCHITECTURE DETECTION #
##########################

if (CYGWIN)
    message(FATAL_ERROR "Cygwin is not supported.")
endif()    

include(CheckTypeSize) 
check_type_size("void*" SIZEOF_VOID_P BUILTIN_TYPES_ONLY) 
configure_file(config.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/config.hpp" @ONLY)
string(REGEX REPLACE "^[ \t]*#define[ \t]+SIZEOF_VOID_P[ \t]+" "" SIZEOF_VOID_P_VALUE ${SIZEOF_VOID_P_CODE})
string(REGEX REPLACE "[^0-9].*$" "" SIZEOF_VOID_P_VALUE "${SIZEOF_VOID_P_VALUE}")
if (SIZEOF_VOID_P_VALUE STREQUAL "8")
    set(ARCH_64BIT TRUE)
else()
    set(ARCH_64BIT FALSE)
endif()
#set(ARCH_64BIT FALSE)
if (ARCH_64BIT)
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DARCH_64BIT")
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
if (COMPILE_OUTPUT MATCHES "ARCH_X86" AND CMAKE_COMPILER_IS_GNUCXX)
    set(ARCH_X86 TRUE)
else()
    set(ARCH_X86 FALSE)
endif()
#set(ARCH_X86 FALSE)
if (ARCH_X86)
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DARCH_X86")
    message(STATUS "ARCH_X86 = TRUE")
else()
    message(STATUS "ARCH_X86 = FALSE")
endif()    



##################
# CUDA DETECTION #
##################

# Workaround for CUDA Toolkit 7.5 and Ubuntu 16.04 LTS
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORCE_INLINES") 

if(EXISTS "/usr/local/cuda-8.0/")
    set(CUDA_TOOLKIT_ROOT_DIR "/usr/local/cuda-8.0/")
	find_package(CUDA 8.0)
endif()
if(NOT CUDA_FOUND AND EXISTS "/usr/local/cuda-7.5/")
    set(CUDA_TOOLKIT_ROOT_DIR "/usr/local/cuda-7.5/")
	find_package(CUDA 7.5)
endif()
if(NOT CUDA_FOUND)
    find_package(CUDA 7.5)
endif()
if(NOT CUDA_FOUND)
    set(ENABLE_CUDA FALSE)
endif()
if (ENABLE_CUDA AND CMAKE_COMPILER_IS_GNUCC)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    string(REGEX MATCHALL "[0-9]+" GCC_VERSION_COMPONENTS ${GCC_VERSION})
    list(GET GCC_VERSION_COMPONENTS 0 GCC_MAJOR)
    list(GET GCC_VERSION_COMPONENTS 1 GCC_MINOR)
    
    if(CUDA_VERSION VERSION_EQUAL "7.5" AND (GCC_VERSION VERSION_EQUAL "5.0.0" OR GCC_VERSION VERSION_GREATER "5.0.0"))
        if (EXISTS "/usr/bin/gcc-4.9" AND EXISTS "/usr/bin/g++-4.9")
            message(WARNING "CUDA Toolkit 7.5 does not support GCC ${GCC_MAJOR}.${GCC_MINOR}. GCC 4.9 will be used instead.")
	    set(CMAKE_C_COMPILER "/usr/bin/gcc-4.9")
	    set(CMAKE_CXX_COMPILER "/usr/bin/g++-4.9")
	else()
            message(WARNING "CUDA Toolkit 7.5 does not support GCC ${GCC_MAJOR}.${GCC_MINOR}. CUDA support is disabled.")
            set(ENABLE_CUDA FALSE)
	endif()
    endif()
endif()
if(ENABLE_CUDA)
    set(MTE_COMPILE_FLAGS "${MTE_COMPILE_FLAGS} -DENABLE_CUDA")
endif()



##########
# OPENCL #
##########

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
find_package(OpenCL 1.2)
if(NOT OpenCL_FOUND)
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
if(UNIX OR (NOT YASM_EXE) OR (NOT ARCH_X86))
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



#######
# C++ #
#######

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
elseif(ARCH_X86)
	file(GLOB CPU_SOURCES
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU10_SSE2Intrinsics.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU10_AVXIntrinsics.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU10_AVX2Intrinsics.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU12_SSE2Intrinsics.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU12_AVXIntrinsics.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU12_AVX2Intrinsics.cpp")
	set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/CPU10_AVXIntrinsics.cpp" PROPERTIES COMPILE_FLAGS -mavx)
	set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/CPU12_AVXIntrinsics.cpp" PROPERTIES COMPILE_FLAGS -mavx)
	set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/CPU10_AVX2Intrinsics.cpp" PROPERTIES COMPILE_FLAGS "-mavx -mavx2")
	set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/CPU12_AVX2Intrinsics.cpp" PROPERTIES COMPILE_FLAGS "-mavx -mavx2")
else()
	file(GLOB CPU_SOURCES
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU10_SSE2Intrinsics.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/CPU12_SSE2Intrinsics.cpp")
endif()
set(SOURCES
	${CORE_SOURCES}
	${CPU_SOURCES}
	${OPENCL_SOURCES})

if(UNIX)
    SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -pthread")
endif()
if(ARCH_X86)
    SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -mmmx -msse -msse2")
endif()
SET(GCC_COVERAGE_COMPILE_FLAGS "${GCC_COVERAGE_COMPILE_FLAGS} -std=c++11 -Wno-deprecated-declarations -O3 -isystem ../BoostPackages/boost_1_61_0 -isystem ../BoostPackages/include")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS} ${MTE_COMPILE_FLAGS}")



########
# CUDA #
########

if(ENABLE_CUDA)
    cuda_include_directories(
        CUDA_INCLUDE_DIR 
        "${MTE_BOOST_DIR}/include" 
        "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/")
    set(CUDA_HOST_COMPILER ${CMAKE_CXX_COMPILER})
    if(ENABLE_CUDA_DES_MULTIPLE_KERNELS_MODE)
        if(CUDA_VERSION_STRING VERSION_EQUAL "8.0" OR CUDA_VERSION_STRING VERSION_GREATER "8.0")
	        set(CUDA_NVCC_FLAGS -DENABLE_CUDA;-DCUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE=0;-gencode=arch=compute_50,code=sm_50;-gencode=arch=compute_52,code=sm_52;-gencode=arch=compute_53,code=sm_53;-gencode=arch=compute_60,code=sm_60;-gencode=arch=compute_61,code=sm_61;-maxrregcount=168)
		else()
	        set(CUDA_NVCC_FLAGS -DENABLE_CUDA;-DCUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE=0;-gencode=arch=compute_50,code=sm_50;-gencode=arch=compute_52,code=sm_52;-gencode=arch=compute_53,code=sm_53;-maxrregcount=168)
		endif()
 		cuda_compile(
			CUDA10_REGISTERS_CU_OUTPUT
			${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers.cu
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher0.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher1.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher2.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher3.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher4.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher5.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher6.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher7.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher8.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher9.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher10.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher11.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher12.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher13.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher14.cu 
				${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers_MultipleKernels/CUDA10_Registers_KernelLauncher15.cu
				STATIC)
    else()
        if(CUDA_VERSION_STRING VERSION_EQUAL "8.0" OR CUDA_VERSION_STRING VERSION_GREATER "8.0")
	        set(CUDA_NVCC_FLAGS -DENABLE_CUDA;-gencode=arch=compute_50,code=sm_50;-gencode=arch=compute_52,code=sm_52;-gencode=arch=compute_53,code=sm_53;-gencode=arch=compute_60,code=sm_60;-gencode=arch=compute_61,code=sm_61;-gencode=arch=compute_61,code=compute_61;-maxrregcount=168)
		else()
	        set(CUDA_NVCC_FLAGS -DENABLE_CUDA;-gencode=arch=compute_50,code=sm_50;-gencode=arch=compute_52,code=sm_52;-gencode=arch=compute_53,code=sm_53;-gencode=arch=compute_53,code=compute_53;-maxrregcount=168)
		endif()
 		cuda_compile(
			CUDA10_REGISTERS_CU_OUTPUT
			${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_Registers.cu
				STATIC)
    endif()

    set(CUDA_NVCC_FLAGS -DENABLE_CUDA)
    cuda_compile(
        CUDA10_SHAREDMEMORY_CU_OUTPUT
        ${CMAKE_CURRENT_SOURCE_DIR}/CUDA10_SharedMemory.cu
	OPTIONS 
            -gencode=arch=compute_20,code=sm_20 
            -gencode=arch=compute_20,code=sm_21 
            -gencode=arch=compute_30,code=sm_30 
            -gencode=arch=compute_32,code=sm_32 
            -gencode=arch=compute_35,code=sm_35 
            -gencode=arch=compute_37,code=sm_37 
            -maxrregcount=42)

    if(CUDA_VERSION_STRING VERSION_EQUAL "8.0" OR CUDA_VERSION_STRING VERSION_GREATER "8.0")
	    set(CUDA_NVCC_FLAGS -DENABLE_CUDA;-gencode=arch=compute_20,code=sm_20;-gencode=arch=compute_20,code=sm_21;-gencode=arch=compute_30,code=sm_30;-gencode=arch=compute_32,code=sm_32;-gencode=arch=compute_35,code=sm_35;-gencode=arch=compute_37,code=sm_37;-gencode=arch=compute_50,code=sm_50;-gencode=arch=compute_52,code=sm_52;-gencode=arch=compute_53,code=sm_53;-gencode=arch=compute_60,code=sm_60;-gencode=arch=compute_61,code=sm_61;-gencode=arch=compute_61,code=compute_61)
	else()
	    set(CUDA_NVCC_FLAGS -DENABLE_CUDA;-gencode=arch=compute_20,code=sm_20;-gencode=arch=compute_20,code=sm_21;-gencode=arch=compute_30,code=sm_30;-gencode=arch=compute_32,code=sm_32;-gencode=arch=compute_35,code=sm_35;-gencode=arch=compute_37,code=sm_37;-gencode=arch=compute_50,code=sm_50;-gencode=arch=compute_52,code=sm_52;-gencode=arch=compute_53,code=sm_53;-gencode=arch=compute_53,code=compute_53)
	endif()
    cuda_compile(
        CUDA12_CU_OUTPUT
        ${CMAKE_CURRENT_SOURCE_DIR}/CUDA12.cu)

    set(CUDA_FILES
        ${CUDA10_REGISTERS_CU_OUTPUT} 
        ${CUDA10_SHAREDMEMORY_CU_OUTPUT}
        ${CUDA12_CU_OUTPUT})
endif()



##############
# EXECUTABLE #
##############

if (ENABLE_OPENCL AND ENABLE_CUDA)
    LINK_LIBRARIES(
        ${OpenCL_LIBRARIES}
        ${CUDA_LIBRARIES}
        boost_system
        boost_iostreams)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        "${MTE_BOOST_DIR}/include"
        "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/"
        ${OpenCL_INCLUDE_DIR}
        "${CUDA_TOOLKIT_ROOT_DIR}include")
	if(ARCH_64BIT)
		link_directories(
		    "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/stage/lib/"
		    ${OpenCL_LIBRARY}
		    "${CUDA_TOOLKIT_ROOT_DIR}lib/x64"
			"${CUDA_TOOLKIT_ROOT_DIR}lib64"
			"${CUDA_TOOLKIT_ROOT_DIR}libx64")
    else()
		link_directories(
		    "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/stage/lib/"
		    ${OpenCL_LIBRARY}
		    "${CUDA_TOOLKIT_ROOT_DIR}lib/Win32"
			"${CUDA_TOOLKIT_ROOT_DIR}lib"
			"${CUDA_TOOLKIT_ROOT_DIR}libWin32")
	endif()
elseif(ENABLE_OPENCL)
    LINK_LIBRARIES(
        ${OpenCL_LIBRARIES}
        boost_system
        boost_iostreams)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        "${MTE_BOOST_DIR}/include"
        "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/"
        ${OpenCL_INCLUDE_DIR})
    link_directories(
        "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/stage/lib/"
        ${OpenCL_LIBRARY})
elseif(ENABLE_CUDA)
    LINK_LIBRARIES(
        ${CUDA_LIBRARIES}
        boost_system
        boost_iostreams)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        "${MTE_BOOST_DIR}/include"
        "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/"
        "${CUDA_TOOLKIT_ROOT_DIR}include")
	if(ARCH_64BIT)
		link_directories(
		    "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/stage/lib/"
		    ${OpenCL_LIBRARY}
		    "${CUDA_TOOLKIT_ROOT_DIR}lib/x64"
			"${CUDA_TOOLKIT_ROOT_DIR}lib64"
			"${CUDA_TOOLKIT_ROOT_DIR}libx64")
    else()
		link_directories(
		    "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/stage/lib/"
		    ${OpenCL_LIBRARY}
		    "${CUDA_TOOLKIT_ROOT_DIR}lib/Win32"
			"${CUDA_TOOLKIT_ROOT_DIR}lib"
			"${CUDA_TOOLKIT_ROOT_DIR}libWin32")
	endif()
else()
    LINK_LIBRARIES(
        boost_system
        boost_iostreams)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        "${MTE_BOOST_DIR}/include"
        "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/")
    link_directories(
        "${MTE_BOOST_DIR}/${MTE_BOOST_PACKAGE}/stage/lib/")
endif()

add_executable(MerikensTripcodeEngine ${SOURCES} ${YASM_FILES} ${CUDA_FILES})
set_target_properties(MerikensTripcodeEngine PROPERTIES LINKER_LANGUAGE CXX)



###########
# INSTALL #
###########

install_programs(/bin FILES ${CMAKE_CURRENT_BINARY_DIR}/MerikensTripcodeEngine)
file(GLOB GCN_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL/bin/*.asm")
install(FILES ${GCN_SOURCE_FILES} DESTINATION etc/MerikensTripcodeEngine/OpenCL/bin)
file(GLOB OPENCL_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL/*.cl")
install(FILES ${OPENCL_SOURCE_FILES} DESTINATION etc/MerikensTripcodeEngine/OpenCL)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/MerikensTripcodeEngine.1" DESTINATION share/man/man1)
if(CMAKE_HOST_UNIX)
    install(CODE "
    EXECUTE_PROCESS(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink MerikensTripcodeEngine merikens-tripcode-engine
       WORKING_DIRECTORY \"${CMAKE_INSTALL_PREFIX}/bin\"
       )
    ")
    install(CODE "
    EXECUTE_PROCESS(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink MerikensTripcodeEngine.1 merikens-tripcode-engine.1
       WORKING_DIRECTORY \"${CMAKE_INSTALL_PREFIX}/share/man/man1\"
       )
    ")
endif(CMAKE_HOST_UNIX)


#############
# UNINSTALL #
#############

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
