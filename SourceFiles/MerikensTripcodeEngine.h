// Meriken's Tripcode Engine
// Copyright (c) 2011-2016 /Meriken/. <meriken.ygch.net@gmail.com>
//
// The initial versions of this software were based on:
// CUDA SHA-1 Tripper 0.2.1
// Copyright (c) 2009 Horo/.IBXjcg
// 
// The code that deals with DES decryption is partially adopted from:
// John the Ripper password cracker
// Copyright (c) 1996-2002, 2005, 2010 by Solar Designer
// DeepLearningJohnDoe's fork of Meriken's Tripcode Engine
// Copyright (c) 2015 by <deeplearningjohndoe at gmail.com>
//
// The code that deals with SHA-1 hash generation is partially adopted from:
// sha_digest-2.2
// Copyright (C) 2009 Jens Thoms Toerring <jt@toerring.de>
// VecTripper 
// Copyright (C) 2011 tmkk <tmkk@smoug.net>
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.



///////////////////////////////////////////////////////////////////////////////
// BUILD OPTIONS                                                             //
///////////////////////////////////////////////////////////////////////////////

// #define REDIRECTION_ONLY
// #define ENGLISH_VERSION
// #define CUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE 



///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILES                                                             //
///////////////////////////////////////////////////////////////////////////////

#define _CRT_RAND_S

#if defined(_WIN32)
// For Win32
#include <windows.h>
#include <process.h>
#include <tlhelp32.h>
#include <ctype.h>
#define COPY_COMMAND "copy"
#define DELETE_COMMAND "del"
#define TYPE_COMMAND "type"
#else
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define __stdcall
#define COPY_COMMAND "cp"
#define DELETE_COMMAND "rm"
#define TYPE_COMMAND "cat"
#endif

#if defined(_WIN32)
#include <conio.h>
#endif

// Standard C++ libraries
#include <cstdlib>
#include <iostream>
#include <atomic>
#include <chrono>
#if !defined(__CUDACC__)
#include <thread>
#endif
#include <mutex>
#ifdef _WIN32
// g++-4 does not have codecvt.
#include <codecvt>
#endif
#include <locale>

// Standard C libraries
#if !defined(_WIN32)
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#endif

// Boost
// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Wunused"

#include <boost/predef.h>
#define BOOST_USE_WINDOWS_H
#include <boost/iostreams/stream.hpp>
#if BOOST_OS_BSD
extern char** environ;
#endif
#include <boost/process.hpp> // Boost.Process 0.5
// #include <boost/process/mitigate.hpp>

// #pragma GCC diagnostic pop

// For MMX/SSE/SSE2/SSSE3 Intrinsics
#ifdef ARCH_X86
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include <emmintrin.h> 
#include <xmmintrin.h>
#include <mmintrin.h>     
#endif

// For CUDA and OpenCL
#ifdef ENABLE_CUDA
#include <cuda.h>
#include <cuda_runtime.h>
#endif
#ifdef ENABLE_OPENCL
#if BOOST_OS_MACOS
#include <OpenCL/OpenCL.h>
#else
#include <CL/cl.h>
#endif
#endif

// MTE
#include "Constants.h"
#include "Types.h"
#include "Macros.h"



///////////////////////////////////////////////////////////////////////////////
// Main.cpp                                                                  //
///////////////////////////////////////////////////////////////////////////////

// Options
extern Options options;

// Application path
extern char applicationPath     [MAX_LEN_FILE_PATH + 1];
extern char applicationDirectory[MAX_LEN_FILE_PATH + 1];

// Input and output files
extern int32_t   numPatternFiles;
extern char  patternFilePathArray[MAX_NUM_PATTERN_FILES][MAX_LEN_FILE_PATH + 1];
extern char tripcodeFilePath[MAX_LEN_FILE_PATH + 1];
extern FILE *tripcodeFile;

// Current and previous status
extern double       matchingProb,     numAverageTrialsForOneMatch;
extern double totalTime;
extern double currentSpeed, currentSpeed_CUDADevice, currentSpeed_CPU, maximumSpeed;
extern uint32_t numValidTripcodes,     numDiscardedTripcodes;
extern uint32_t prevNumValidTripcodes, prevNumDiscardedTripcodes;
extern double     numGeneratedTripcodes;
extern double prevNumGeneratedTripcodes;
extern int32_t prevLineCount;
#define TIME_SINCE_EPOCH_IN_MILLISECONDS ((std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())).count())

// Search Parameters
extern int32_t searchMode;
extern int32_t lenTripcode;
extern int32_t lenTripcodeKey;

// Character tables
extern int32_t           numFirstByte;
extern int32_t           numSecondByte;
extern int32_t           numOneByte;
extern unsigned char keyCharTable_OneByte             [SIZE_KEY_CHAR_TABLE];
extern unsigned char keyCharTable_FirstByte           [SIZE_KEY_CHAR_TABLE];
extern unsigned char keyCharTable_SecondByte          [SIZE_KEY_CHAR_TABLE];
extern unsigned char keyCharTable_SecondByteAndOneByte[SIZE_KEY_CHAR_TABLE];
extern char          base64CharTable[64];
extern void          CreateCharacterTables(void);

// Key bitmap
extern unsigned char chunkBitmap[];
extern unsigned char mediumChunkBitmap[];
extern unsigned char smallChunkBitmap[];
extern unsigned char compactMediumChunkBitmap[];
extern unsigned char compactSmallChunkBitmap[];

// GPUs
extern int32_t CUDADeviceCount;
extern int32_t searchDevice;

// For multi-threading
#ifndef __CUDACC__
extern spinlock gcn_assembler_spinlock;
extern std::mutex boost_process_mutex;
extern mte::named_event termination_event;
extern mte::named_event pause_event;
#endif

//
extern void          AddToNumGeneratedTripcodesByCPU(uint32_t num);
extern void          AddToNumGeneratedTripcodesByGPU(uint32_t num);
extern void          SetCharactersInTripcodeKey(unsigned char *key, int32_t n);
extern void          SetCharactersInTripcodeKeyForSHA1Tripcode(unsigned char *key);
extern unsigned char RandomByte();
extern BOOL          IsValidKey(unsigned char *key);
extern void          CreateKey8AndKey9(unsigned char *key);

// 
extern void SetPauseState(BOOL state);
extern BOOL GetPauseState();
extern void SetErrorState();
extern BOOL GetErrorState();
extern void SetTerminationState();
extern BOOL GetTerminationState();
extern const char *GetErrorMessage(int32_t errorCode);

//
#ifdef ENABLE_CUDA
extern void UpdateCUDADeviceStatus  (struct CUDADeviceSearchThreadInfo   *info, const char *status);
#endif
#ifdef ENABLE_OPENCL
extern void UpdateOpenCLDeviceStatus(struct OpenCLDeviceSearchThreadInfo *info, const char *status);
extern void UpdateOpenCLDeviceStatus_ChildProcess(struct OpenCLDeviceSearchThreadInfo *info, const char *status, double currentSpeed, double averageSpeed, double totalNumGeneratedTripcodes, uint32_t numDiscardedTripcodes);
#endif

//
extern void show_cursor();
extern void reset_cursor_pos(int n);

// Output
extern double ProcessGPUOutput(unsigned char *key, GPUOutput *outputArray, uint32_t sizeOutputArray, BOOL newFormat);
extern void   ProcessValidTripcodePair(unsigned char *tripcode, unsigned char *key);
extern void   ProcessInvalidTripcodePair(unsigned char *tripcode, unsigned char *key);

// Others
extern BOOL IsFirstByteSJIS(unsigned char ch);
extern void sleep_for_milliseconds(uint32_t milliseconds);
extern int execute_system_command(const char *command);



///////////////////////////////////////////////////////////////////////////////
// Patterns.cu                                                       //
///////////////////////////////////////////////////////////////////////////////

extern void LoadTargetPatterns(BOOL displayProgress);
extern void ProcessMatch        (unsigned char *tripcode, unsigned char *key);
extern void ProcessPossibleMatch(unsigned char *tripcode, unsigned char *key);
extern BOOL IsTripcodeChunkValid(unsigned char *tripcode);

extern ExpandedPattern *expandedPatternArray;
extern uint32_t     numExpandedPatterns;
extern uint32_t     sizeExpandedPatternArray;
extern int32_t              minLenExpandedPattern;
extern int32_t              maxLenExpandedPattern;
extern uint32_t    *tripcodeChunkArray;        
extern uint32_t     numTripcodeChunk;
extern uint32_t     sizeTripcodeChunkArray;
extern RegexPattern    *regexPatternArray;
extern uint32_t              sizeRegexPatternArray;
extern uint32_t              numRegexPattern;
extern BOOL             searchForSpecialPatternsOnCPU;



///////////////////////////////////////////////////////////////////////////////
// Testing.cu                                                            //
///////////////////////////////////////////////////////////////////////////////

extern void TestNewCode();



///////////////////////////////////////////////////////////////////////////////
// BITSLICED DES                                                             //
///////////////////////////////////////////////////////////////////////////////

#ifdef USE_YASM

extern "C" void CPU_DES_SBoxes1_asm_x64(void *context, int64_t keyScheduleIndexBase);
extern "C" void CPU_DES_SBoxes2_asm_x64(void *context, int64_t keyScheduleIndexBase);

#ifdef _M_X64
extern "C" void DES_Crypt25_x64_SSE2        (void *context);
extern "C" void DES_Crypt25_x64_SSE2_Nehalem(void *context);
extern "C" void DES_Crypt25_x64_AVX         (void *context);
extern "C" void DES_Crypt25_x64_AVX2        (void *context);
#else
extern "C" void DES_Crypt25_x86_SSE2        (void *context);
extern "C" void DES_Crypt25_x86_SSE2_Nehalem(void *context);
extern "C" void DES_Crypt25_x86_AVX         (void *context);
extern "C" void DES_Crypt25_x86_AVX2        (void *context);
#endif

#endif



///////////////////////////////////////////////////////////////////////////////
// OPENCL                                                                    //
///////////////////////////////////////////////////////////////////////////////

#ifdef ENABLE_OPENCL

extern const char     *GetProductNameForOpenCLDevice(char *vendor, char *name, cl_uint numComputeUnits);
extern void            GetParametersForOpenCLDevice(cl_device_id deviceID, char *sourceFile, size_t *numWorkItemsPerComputeUnit, size_t *localWorkSize, char *options);
extern const char     *ConvertOpenCLErrorCodeToString(cl_int openCLError);
extern void __stdcall  OnOpenCLError(const char *errorInfo, const void *privateInfo, size_t sizePrivateInfo, void *userData);
extern void            StartChildProcessForOpenCLDevice(OpenCLDeviceSearchThreadInfo *info);
extern void            Thread_RunChildProcessForOpenCLDevice(OpenCLDeviceSearchThreadInfo *info);

#endif



///////////////////////////////////////////////////////////////////////////////
// VERFICATION                                                               //
///////////////////////////////////////////////////////////////////////////////

extern BOOL VerifySHA1Tripcode (unsigned char *tripcode, unsigned char *key);
extern BOOL VerifyDESTripcode  (unsigned char *tripcode, unsigned char *key);
extern BOOL IsTripcodeDuplicate(unsigned char *tripcode);
extern void GenerateDESTripcode(unsigned char *tripcode, unsigned char *key);
extern void Generate10CharTripcodes(TripcodeKeyPair *p, int32_t numTripcodes);



///////////////////////////////////////////////////////////////////////////////
// SEARCH THREADS                                                            //
///////////////////////////////////////////////////////////////////////////////

extern void Thread_SearchForSHA1TripcodesOnCPU();
extern void Thread_SearchForDESTripcodesOnCPU();

#ifdef ENABLE_CUDA
extern void Thread_SearchForSHA1TripcodesOnCUDADevice(CUDADeviceSearchThreadInfo *info);
extern void Thread_SearchForDESTripcodesOnCUDADevice(CUDADeviceSearchThreadInfo *info);
extern void Thread_SearchForDESTripcodesOnCUDADevice_Registers(CUDADeviceSearchThreadInfo *info);
#endif

#ifdef ENABLE_OPENCL
extern void Thread_SearchForSHA1TripcodesOnOpenCLDevice(OpenCLDeviceSearchThreadInfo *info);
extern void Thread_SearchForDESTripcodesOnOpenCLDevice(OpenCLDeviceSearchThreadInfo *info);
extern void Thread_RunChildProcessForOpenCLDevice(OpenCLDeviceSearchThreadInfo *info);
#endif

extern void DES_CreateExpansionFunction(char *saltString, unsigned char *expansionFunction);
extern const char          charToIndexTableForDES[0x100];
extern const unsigned char expansionTable[48];
// extern unsigned char       expansionFunction[96];
extern unsigned char charTableForKagami[256];



///////////////////////////////////////////////////////////////////////////////
// CPUID                                                                     //
///////////////////////////////////////////////////////////////////////////////

#ifdef ENABLE_AVX
extern bool IsAVXSupported();
extern bool IsAVX2Supported();
#endif

extern     BOOL IsCPUBasedOnNehalemMicroarchitecture();
