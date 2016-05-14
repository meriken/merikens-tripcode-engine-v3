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
// INCLUDE FILE(S)                                                           //
///////////////////////////////////////////////////////////////////////////////

#include "MerikensTripcodeEngine.h"
#include <random>
#include <climits>



///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES, CONSTANTS, AND MACROS                                   //
///////////////////////////////////////////////////////////////////////////////

Options options = {
	DEFAULT_OPTION_GPU_INDEX,                       // int32_t  GPUIndex;
	DEFAULT_OPTION_CUDA_NUM_BLOCKS_PER_SM,          // int32_t  numBlocksPerSM;
	DEFAULT_OPTION_BEEP_WHEN_NEW_TRIPCODE_IS_FOUND, // BOOL beepWhenNewTripcodeIsFound;
	DEFAULT_OPTION_OUTPUT_INVALID_TRIPCODE,         // BOOL outputInvalidTripcode;
	DEFAULT_OPTION_WARN_SPEED_DROP,                 // BOOL warnSpeedDrop;
	DEFAULT_OPTION_SEARCH_DEVICE,                   // int32_t  searchDevice;
	DEFAULT_OPTION_TEST_NEW_CODE,                   // BOOL testNewCode;
	DEFAULT_OPTION_NUM_CPU_SEARCH_THREADS,          // int32_t  numCPUSearchThreads;
	DEFAULT_OPTION_REDIRECTION,                     // BOOL redirection;
	DEFAULT_OPTION_OPENCL_NUM_NUM_WORK_ITEMS_PER_CU, // int32_t  openCLNumWorkItemsPerCU;
	DEFAULT_OPTION_OPENCL_NUM_WORK_ITEMS_PER_WG,     // int32_t  openCLNumWorkItemsPerWG;
	DEFAULT_OPTION_OPENCL_NUM_THREADS_PER_AMD_GPU,   // int32_t  openCLNumThreads;
	DEFAULT_OPTION_USE_ONE_BYTE_CHARACTERS_FOR_KEYS, // BOOL useOneByteCharactersForKeys;
	DEFAULT_OPTION_SEARCH_FOR_HISEKI_ON_CPU,
	DEFAULT_OPTION_SEARCH_FOR_KAKUHI_ON_CPU,
	DEFAULT_OPTION_SEARCH_FOR_KAIBUN_ON_CPU,
	DEFAULT_OPTION_SEARCH_FOR_YAMABIKO_ON_CPU,
	DEFAULT_OPTION_SEARCH_FOR_SOUREN_ON_CPU,
	DEFAULT_OPTION_SEARCH_FOR_KAGAMI_ON_CPU,
	DEFAULT_OPTION_USE_OPENCL_FOR_CUDA_DEVICES,
	DEFAULT_OPTION_IS_AVX_ENABLED,
	DEFAULT_OPTION_USE_ONLY_ASCII_CHARACTERS_FOR_KEYS,
	DEFAULT_OPTION_MAXIMIZE_KEY_SPACE,
	DEFAULT_OPTION_IS_AVX2_ENABLED,
	DEFAULT_OPTION_OPENCL_RUN_CHILD_PROCESSES_FOR_MULTIPLE_DEVICES, // BOOL openCLRunChildProcesses;
	DEFAULT_OPTION_OPENCL_NUM_PROCESSES_PER_AMD_GPU, // int32_t  openCLNumProcesses;
	DEFAULT_OPTION_CHECK_TRIPCODES,                  // BOOL checkTripcodes;
	DEFAULT_OPTION_ENABLE_GCN_ASSEMBLER,             // BOOL enableGCNAssembler;
};

// Search Parameters
int32_t  lenTripcode    = 10;
int32_t  lenTripcodeKey = 10;

// Application path
char applicationPath     [MAX_LEN_FILE_PATH + 1];
char applicationDirectory[MAX_LEN_FILE_PATH + 1];

// Input and output files
int32_t   numPatternFiles = 0;
char  patternFilePathArray[MAX_NUM_PATTERN_FILES][MAX_LEN_FILE_PATH + 1];
char  tripcodeFilePath    [MAX_LEN_FILE_PATH + 1];
FILE *tripcodeFile = NULL;

// Interprocess communication
std::atomic_bool pause_state       = ATOMIC_VAR_INIT(false);
std::atomic_bool termination_state = ATOMIC_VAR_INIT(false);
std::atomic_bool error_state       = ATOMIC_VAR_INIT(false);
mte::named_event termination_event;
mte::named_event pause_event;

// GPUs
int32_t           CUDADeviceCount = 0;
int32_t           openCLDeviceCount = 0;
#ifdef ENABLE_OPENCL
cl_device_id     *openCLDeviceIDArray = NULL;
#endif
int32_t           searchDevice = SEARCH_DEVICE_NIL;

// Character tables
int32_t numFirstByte  = 0;
int32_t numSecondByte = 0;
int32_t numOneByte    = 0;
unsigned char keyCharTable_OneByte             [SIZE_KEY_CHAR_TABLE];
unsigned char keyCharTable_FirstByte           [SIZE_KEY_CHAR_TABLE];
unsigned char keyCharTable_SecondByte          [SIZE_KEY_CHAR_TABLE];
unsigned char keyCharTable_SecondByteAndOneByte[SIZE_KEY_CHAR_TABLE];
char base64CharTable[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '/',
};

// Current and previous status
double       matchingProb,     numAverageTrialsForOneMatch;
double       totalTime = 0;
double       currentSpeed_thisProcess = 0, currentSpeed_thisProcess_GPU = 0, currentSpeed = 0, currentSpeed_GPU = 0, currentSpeed_CPU = 0, maximumSpeed = 0;
unsigned int     numValidTripcodes = 0,     numDiscardedTripcodes = 0;
unsigned int prevNumValidTripcodes = 0, prevNumDiscardedTripcodes = 0;
double           totalNumGeneratedTripcodes = 0;
double           totalNumGeneratedTripcodes_GPU = 0;
double           totalNumGeneratedTripcodes_CPU = 0;
double       prevTotalNumGeneratedTripcodes = 0;
double       prevTotalNumGeneratedTripcodes_GPU = 0;
double       prevTotalNumGeneratedTripcodes_CPU = 0;
int32_t prevLineCount = 0;



// Search mode
int32_t searchMode = SEARCH_MODE_NIL;

// For multi-threading
int32_t                                  numCUDADeviceSearchThreads        = 0;
struct CUDADeviceSearchThreadInfo   *CUDADeviceSearchThreadInfoArray   = NULL;
std::thread                              **cuda_device_search_threads       = NULL;
int32_t                                  numOpenCLDeviceSearchThreads      = 0;
struct OpenCLDeviceSearchThreadInfo *openCLDeviceSearchThreadInfoArray = NULL;
std::thread                              **opencl_device_search_threads = NULL;
int32_t                                  numCPUSearchThreads               = 0;
std::thread                              **cpu_search_threads = NULL;
BOOL                                 openCLRunChildProcesses = FALSE;
static spinlock num_generated_tripcodes_spinlock;
static spinlock process_tripcode_pair_spinlock;
static spinlock current_state_spinlock;
static spinlock cuda_device_search_thread_info_array_spinlock;
static spinlock opencl_device_search_thread_info_array_spinlock;
static spinlock system_command_spinlock;
spinlock gcn_assembler_spinlock;
spinlock boost_process_spinlock;
uint32_t     numGeneratedTripcodes_GPU;
uint32_t     numGeneratedTripcodesByGPUInMillions;
uint32_t     numGeneratedTripcodes_CPU;
uint32_t     numGeneratedTripcodesByCPUInMillions;

//
static std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned int> random_bytes_engine(std::random_device{}());
static spinlock random_byte_spinlock;



///////////////////////////////////////////////////////////////////////////////
// TABLES                                                                    //
///////////////////////////////////////////////////////////////////////////////

unsigned char charTableForKagami[256] = {
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '.', '\0',
	'0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '8', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', 'A', '\0', '\0', '\0', '\0', '\0', '\0', 'H', 'I', '\0', '\0', '\0', 'M', '\0', 'O',
	'\0', '\0', '\0', '\0', 'T', 'U', 'V', 'W', 'X', 'Y', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', 'd', '\0', 'b', '\0', '\0', '\0', '\0', 'i', '\0', '\0', 'l', '\0', '\0', 'o',
	'q', 'p', '\0', '\0', '\0', '\0', 'v', 'w', 'x', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
};

// The following table was adopted from:
// http://sourceforge.jp/projects/naniya/wiki/2chtrip#h2-Salt.E7.94.9F.E6.88.90.E8.A6.8F.E5.89.87

unsigned char charTableForSeed[256] = {
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
	'G', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e',
	'f', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
	'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
};

const char charToIndexTableForDES[0x100] = {
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
	0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
	0x23, 0x24, 0x25, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
	0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
	0x3d, 0x3e, 0x3f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
};

const unsigned char expansionTable[48] = {
	31, 0, 1, 2, 3, 4,
	3, 4, 5, 6, 7, 8,
	7, 8, 9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31, 0
};



///////////////////////////////////////////////////////////////////////////////
// FUNCTIONS                                                                 //
///////////////////////////////////////////////////////////////////////////////

int execute_system_command(const char *command)
{
	int ret;

#if defined(_WIN32) || defined(__CYGWIN__)
	std::string wrapped_command;
	wrapped_command += "cmd /C \"";
	wrapped_command += command;
	wrapped_command += "\"";
	// std::cout << wrapped_command << std::endl;
	system_command_spinlock.lock();
	ret = system(wrapped_command.data());
	system_command_spinlock.unlock();
#else
	system_command_spinlock.lock();
	ret = system(command);
	system_command_spinlock.unlock();
#endif

	return ret;
}

void DES_CreateExpansionFunction(char *saltString, unsigned char *expansionFunction)
{
	unsigned char saltChar1 = '.', saltChar2 = '.';
	int32_t salt;
	int32_t mask;
	int32_t src, dst;

	if (saltString[0]) {
		saltChar1 = saltString[0];
		if (saltString[1])
			saltChar2 = saltString[1];
	}
	salt = charToIndexTableForDES[saltChar1]
		| (charToIndexTableForDES[saltChar2] << 6);

	mask = 1;
	for (dst = 0; dst < 48; dst++) {
		if (dst == 24) mask = 1;

		if (salt & mask) {
			if (dst < 24) src = dst + 24; else src = dst - 24;
		}
		else src = dst;

		expansionFunction[dst] = expansionTable[src];
		expansionFunction[dst + 48] = expansionTable[src] + 32;

		mask <<= 1;
	}
}

void SetPauseState(BOOL newPauseState)
{
	pause_state.store(newPauseState);
}

BOOL GetPauseState()
{
	return pause_state.load();
}

BOOL UpdatePauseState()
{
	if (pause_event.is_open())
		pause_state.store(pause_event.poll());
	return pause_state.load();
}

void SetErrorState()
{
	error_state.store(true);
}

BOOL GetErrorState()
{
	return error_state.load();
}

void SetTerminationState()
{
	termination_state.store(true);
}

BOOL GetTerminationState()
{
	return termination_state.load();
}

BOOL UpdateTerminationState()
{
	if (termination_event.is_open())
		termination_state.store(termination_event.poll());
	return termination_state.load();
}

void sleep_for_milliseconds(uint32_t milliseconds)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

const char *GetErrorMessage(int32_t errorCode)
{
	switch (errorCode) {
    case ERROR_INVALID_TARGET_PATTERN: 
		return "ERROR_INVALID_TARGET_PATTERN";
    case ERROR_INVALID_REGEX: 
		return "ERROR_INVALID_REGEX";
    case ERROR_PATTERN_TOO_LONG: 
		return "ERROR_PATTERN_TOO_LONG";
    case ERROR_PATTERN_TOO_SHORT: 
		return "ERROR_PATTERN_TOO_SHORT";
    case ERROR_CUDA:
		return "CUDA fucnction call failed.";
    case ERROR_NO_MEMORY: 
		return "ERROR_NO_MEMORY";
    case ERROR_PATTERN_FILE: 
		return "ERROR_PATTERN_FILE";
    case ERROR_IGNORE_DIRECTIVE:
		return "ERROR_IGNORE_DIRECTIVE";
    case ERROR_NO_TARGET_PATTERNS: 
		return "ERROR_NO_TARGET_PATTERNS";
    case ERROR_CRYPTOGRAPHIC_SERVICE: 
		return "ERROR_CRYPTOGRAPHIC_SERVICE";
    case ERROR_INVALID_OPTION: 
		return "ERROR_INVALID_OPTION";
    case ERROR_TRIPCODE_FILE:
		return "ERROR_TRIPCODE_FILE";
    case ERROR_SEARCH_THREAD: 
		return "ERROR_SEARCH_THREAD";
    case ERROR_MUTEX:
		return "ERROR_MUTEX";
    case ERROR_ASSERTION:
		return "Assertion failed.";
    case ERROR_OPENCL:
		return "OpenCL fucnction call failed.";
    case ERROR_DES: 
		return "ERROR_DES";
    case ERROR_SHA1: 
		return "ERROR_SHA1";
    case ERROR_INTEL_HD_GRAPHICS:
		return "ERROR_INTEL_HD_GRAPHICS";
    case ERROR_CHILD_PROCESS:
		return "ERROR_CHILD_PROCESS";
    case ERROR_TRIPCODE_VERIFICATION_FAILED: 
		return "A corrupt tripcode was generated.\n  The hardware or device driver may be malfunctioning.\n  Please check the temperatures of CPU(s) and GPU(s).";
    case ERROR_EVENT: 
		return "ERROR_EVENT";
    case ERROR_SEARCH_THREAD_UNRESPONSIVE:
		return "ERROR_SEARCH_THREAD_UNRESPONSIVE";
    case ERROR_GCN_ASSEMBLER: 
		return "GCN assembler failed.";
    default: return "ERROR_UNKNOWN";
	}
}

unsigned char RandomByte()
{
	random_byte_spinlock.lock();
	unsigned char b = random_bytes_engine() & 0xff;
	random_byte_spinlock.unlock();
	return b;
}

void ReleaseResources()
{
	RELEASE_AND_SET_TO_NULL(expandedPatternArray, free);
	RELEASE_AND_SET_TO_NULL(tripcodeChunkArray,   free);
	RELEASE_AND_SET_TO_NULL(regexPatternArray,    free);
	if (tripcodeFile) {
		RELEASE_AND_SET_TO_NULL(tripcodeFile,     fclose);
	}
}

void PrintUsage()
{
	printf("Usage: %s [-c] [-g] [-d device_no] [-x blocks_per_SM] [-y global_work_size] [-z local_work_size] [-o tripcode_file] [-f pattern_file] [-i] [-w]\n", COMMAND);
	getchar();
	exit(-1);
}

void reset_cursor_pos(int n)
{
#if (defined(_WIN32) || defined(_WIN64)) && !(__CYGWIN__)
	CONSOLE_SCREEN_BUFFER_INFO scrnBufInfo;
	COORD                      cursorPos;
	if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &scrnBufInfo))
		return;
	cursorPos.X = 0;
	cursorPos.Y = (scrnBufInfo.dwCursorPosition.Y + n) >= 0
		? (scrnBufInfo.dwCursorPosition.Y + n)
		: 0;
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), cursorPos);
#else
	std::cout << "\n\033[1A";
	if (n > 0) {
		std::cout << "\033[" << n << "B";
	} else if (n < 0) {
		std::cout << "\033[" << -n << "A";
	}
#endif
}

#if defined(_WIN32) || defined(_WIN64)

void hide_cursor()
{
	CONSOLE_CURSOR_INFO info;

	info.bVisible = false;
	info.dwSize = 100;
	SetConsoleCursorInfo((HWND)GetStdHandle(STD_OUTPUT_HANDLE), &info);
}

void show_cursor()
{
	CONSOLE_CURSOR_INFO info;

	info.bVisible = true;
	info.dwSize = 100;
	SetConsoleCursorInfo((HWND)GetStdHandle(STD_OUTPUT_HANDLE), &info); 
}

#else

void hide_cursor()
{
}

void show_cursor()
{
}

#endif

void CreateKey8AndKey9(unsigned char *key)
{
	ASSERT(lenTripcode == 10);
	if (options.useOneByteCharactersForKeys) {
		key[8] = keyCharTable_OneByte[RandomByte()];
		key[9] = keyCharTable_OneByte[RandomByte()];
	} else {
		BOOL isSecondByte = FALSE;
		for (int32_t i = 0; i < 8; ++i) {
			if (!isSecondByte) {
				isSecondByte = IS_FIRST_BYTE_SJIS_FULL(key[i]);
			} else {
				isSecondByte = FALSE;
			}
		}
		if (isSecondByte) {
			key[8] = keyCharTable_SecondByte[RandomByte()];
			key[9] = keyCharTable_OneByte   [RandomByte()];
		} else {
			key[8] = keyCharTable_FirstByte[RandomByte()];
			key[9] = (IS_FIRST_BYTE_SJIS_FULL(key[8]))
							? keyCharTable_SecondByte[RandomByte()]
							: keyCharTable_OneByte   [RandomByte()];
		}
	}
}

double ProcessGPUOutput(unsigned char *partialKey, GPUOutput *outputArray, uint32_t sizeOutputArray, BOOL newFormat)
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE     + 1];
	unsigned char  key     [MAX_LEN_TRIPCODE_KEY + 1];
	double numGeneratedTripcodesInThisOutput = 0;
	
	tripcode[lenTripcode   ] = '\0';
	key     [lenTripcodeKey] = '\0';
	memcpy(key, partialKey, lenTripcodeKey);
	for (uint32_t indexOutput = 0; indexOutput < sizeOutputArray; indexOutput++){
		GPUOutput *output = &outputArray[indexOutput];
		AddToNumGeneratedTripcodesByGPU(output->numGeneratedTripcodes);
		numGeneratedTripcodesInThisOutput += output->numGeneratedTripcodes;
		if (output->numMatchingTripcodes > 0) {
			memcpy(tripcode, output->pair.tripcode.c, lenTripcode);
			if (lenTripcode == 12 && newFormat) {
				memcpy(key, output->pair.key.c, 4);
				key[7]  = output->pair.key.c[7];
				key[11] = output->pair.key.c[11];
			} else if (lenTripcode == 12) {
				memcpy(key + 7,  output->pair.key.c + 7, lenTripcode - 7);
			} else {
				ASSERT(lenTripcode == 10);
				memcpy(key,  output->pair.key.c, 8);
				CreateKey8AndKey9(key);
			}
			//printf("{%s, %s}\n", tripcode, key);
			ERROR0(!IsTripcodeChunkValid(tripcode),
				   ERROR_TRIPCODE_VERIFICATION_FAILED, 
				   GetErrorMessage(ERROR_TRIPCODE_VERIFICATION_FAILED));
			ProcessPossibleMatch(tripcode, key);
		}
	}
	return numGeneratedTripcodesInThisOutput;
}

BOOL IsValidKey(unsigned char *key)
{
	int32_t i;
	BOOL isSecondByteSJIS = FALSE;
	char results[13] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	
	if (key[0] == '#' || key[0] == '$') {
#ifdef DEBUG_PRINT_INVALID_KEY_INFO
		printf("  results: %c                                                     \n", key[0]);
#endif
		return FALSE;
	}

	for (i = 0; i < lenTripcode; ++i) {
		if (!isSecondByteSJIS && IS_ONE_BYTE_KEY_CHAR(key[i])) {
			// Don't do anything
			results[i] = 'O';
		} else if (!isSecondByteSJIS && i < lenTripcode - 1 && IS_FIRST_BYTE_SJIS_FULL(key[i])) {
			isSecondByteSJIS = TRUE;
			results[i] = '1';
		} else if (isSecondByteSJIS && IS_SECOND_BYTE_SJIS(key[i])) {
		    isSecondByteSJIS = FALSE;
		    if (!IS_VALID_SJIS_CHAR(key[i - 1], key[i])) {
#ifdef DEBUG_PRINT_INVALID_KEY_INFO
				printf("  results: %sx                                                     \n", results);
				printf("  key[%2d]: 0x%02x ('%c')                                            \n", i, key[i], key[i]);
#endif
				return FALSE;
			}
			results[i] = '2';
		} else {
#ifdef DEBUG_PRINT_INVALID_KEY_INFO
			printf("  results: %sX                                                     \n", results);
			printf("  key[%2d]: 0x%02x ('%c')                                            \n", i, key[i], key[i]);
#endif
			return FALSE;
		}
	}
	return TRUE;
}

void CreateCharacterTables(void)
{
	unsigned char keyChar;
	int32_t i;

#if FALSE
	for (i = 0; i < 64; ++i)
		base64CharTable[i] = i + ((i < 26) ?  'A'       :
		                          (i < 52) ? ('a' - 26) :
		                          (i < 62) ? ('0' - 52) :
		                                     ('.' - 62));
#endif

	numFirstByte = numSecondByte = numOneByte = 0;

	// Set keyCharTable_OneByte[]
	if (options.useOnlyASCIICharactersForKeys) {
		do {
			keyChar = RandomByte();
		} while (!IS_ASCII_KEY_CHAR(keyChar));
		for (i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
			keyChar = ((int32_t)keyChar + 1) & 0xff;
			while (!IS_ASCII_KEY_CHAR(keyChar))
				keyChar = ((int32_t)keyChar + 1) & 0xff;
			keyCharTable_OneByte[i] = keyChar;
		}
	} else {
		do {
			keyChar = RandomByte();
		} while (!IS_ONE_BYTE_KEY_CHAR(keyChar));
		for (i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
			keyChar = ((int32_t)keyChar + 1) & 0xff;
			while (!IS_ONE_BYTE_KEY_CHAR(keyChar))
				keyChar = ((int32_t)keyChar + 1) & 0xff;
			keyCharTable_OneByte[i] = keyChar;
		}
	}

	// Set keyCharTable_FirstByte[], keyCharTable_SecondByte[], and keyCharTable_SecondByteAndOneByte[].
	if (options.useOnlyASCIICharactersForKeys) {
		for (i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
			keyCharTable_FirstByte [i]           = keyCharTable_OneByte[i];
			keyCharTable_SecondByte[i]           = keyCharTable_OneByte[i];
			keyCharTable_SecondByteAndOneByte[i] = keyCharTable_OneByte[i];
		}
		for (int32_t i = 0; i < 256; ++i) {
			if (IS_ASCII_KEY_CHAR(i)) {
				++numFirstByte;
				++numSecondByte;
				++numOneByte;
			}
		}
	} else if (options.useOneByteCharactersForKeys) {
		for (i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
			keyCharTable_FirstByte           [i] = keyCharTable_OneByte[i];
			keyCharTable_SecondByte          [i] = keyCharTable_OneByte[i];
			keyCharTable_SecondByteAndOneByte[i] = keyCharTable_OneByte[i];
		}
		for (int32_t i = 0; i < 256; ++i) {
			if (IS_ONE_BYTE_KEY_CHAR(i)) {
				++numFirstByte;
				++numSecondByte;
				++numOneByte;
			}
		}
	} else {
		// Set keyCharTable_FirstByte[].
		do {
			keyChar = RandomByte();
		} while (!(IS_ONE_BYTE_KEY_CHAR(keyChar) || IsFirstByteSJIS(keyChar)));
		for (i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
			keyCharTable_FirstByte[i] = keyChar;
			do {
				keyChar = ((int32_t)keyChar + 1) & 0xff;
			} while (!(IS_ONE_BYTE_KEY_CHAR(keyChar) || IsFirstByteSJIS(keyChar)));
		}

		// Set keyCharTable_SecondByte[].
		do {
			keyChar = RandomByte();
		} while (!IS_SECOND_BYTE_SJIS(keyChar));
		for (i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
			keyCharTable_SecondByte[i] = keyChar;
			do {
				keyChar = ((int32_t)keyChar + 1) & 0xff;
			} while (!IS_SECOND_BYTE_SJIS(keyChar));
		}

		// Set keyCharTable_SecondByteAndOneByte[].
		do {
			keyChar = RandomByte();
		} while (!(IS_SECOND_BYTE_SJIS(keyChar) && IS_ONE_BYTE_KEY_CHAR(keyChar)));
		for (i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
			keyCharTable_SecondByteAndOneByte[i] = keyChar;
			do {
				keyChar = ((int32_t)keyChar + 1) & 0xff;
			} while (!(IS_SECOND_BYTE_SJIS(keyChar) && IS_ONE_BYTE_KEY_CHAR(keyChar)));
		}

		// Count characters in each table.
		for (int32_t i = 0; i < 256; ++i) {
			if (IS_ONE_BYTE_KEY_CHAR(i) || IsFirstByteSJIS(i) ) ++numFirstByte;
			if (                           IS_SECOND_BYTE_SJIS(i)) ++numSecondByte;
			if (IS_ONE_BYTE_KEY_CHAR(i)                          ) ++numOneByte;
		}
	}
#if FALSE
	printf("numFirstByte  = %d\n", numFirstByte);
	printf("numSecondByte = %d\n", numSecondByte);
	printf("numOneByte    = %d\n", numOneByte);
#endif
}

void DisplayCopyrights()
{
#ifdef ENGLISH_VERSION
	printf("%s English\n", PRODUCT_NAME);
	printf("[compiled at %s on %s (PST)]\n", __TIME__, __DATE__);
	printf("Copyright (C) 2014-2016 !/Meriken/. <meriken.ygch.net@gmail.com>\n");
#else
	printf("%s\n", PRODUCT_NAME);
	printf("[compiled at %s on %s (PST)]\n", __TIME__, __DATE__);
	printf("Copyright (C) 2011-2016 %c%c/Meriken/. <meriken.ygch.net@gmail.com>\n", 0x81, 0x9f);
#endif
	printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
    printf("This is free software, and you are welcome to redistribute it\n");
    printf("under certain conditions.\n");
    printf("\n");
}

#ifdef ENABLE_CUDA

void UpdateCUDADeviceStatus(struct CUDADeviceSearchThreadInfo *info, const char *status)
{
	cuda_device_search_thread_info_array_spinlock.lock();
	strcpy(info->status, status);
	info->timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
	cuda_device_search_thread_info_array_spinlock.unlock();
}

#endif

#ifdef ENABLE_OPENCL

void UpdateOpenCLDeviceStatus(struct OpenCLDeviceSearchThreadInfo *info, const char *status)
{
	opencl_device_search_thread_info_array_spinlock.lock();
	ASSERT(!info->runChildProcess);
	strcpy(info->status, status);
	info->timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
	opencl_device_search_thread_info_array_spinlock.unlock();
}

void UpdateOpenCLDeviceStatus_ChildProcess(struct OpenCLDeviceSearchThreadInfo *info, const char *status, double currentSpeed, double averageSpeed, double totalNumGeneratedTripcodes, uint32_t numDiscardedTripcodes)
{
	opencl_device_search_thread_info_array_spinlock.lock();
	ASSERT(info->runChildProcess);
	strcpy(info->status, status);
	info->currentSpeed = currentSpeed;
	info->averageSpeed = averageSpeed;
	info->totalNumGeneratedTripcodes = totalNumGeneratedTripcodes;
	info->numDiscardedTripcodes = numDiscardedTripcodes;
	info->timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
	opencl_device_search_thread_info_array_spinlock.unlock();
}

#endif

void CheckSearchThreads()
{
#ifdef ENABLE_CUDA
	cuda_device_search_thread_info_array_spinlock.lock();
	for (int32_t index = 0; index < numCUDADeviceSearchThreads; ++index) {
		struct CUDADeviceSearchThreadInfo *info = &CUDADeviceSearchThreadInfoArray[index];
		uint64_t  currentTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		uint64_t  deltaTime = currentTime - info->timeLastUpdated;
		// if (deltaTime > 60 * 1000)
		//	strcpy(info->status, "Search thread became unresponsive.");
		//ERROR0(deltaTime > 1 * 60 * 1000, ERROR_SEARCH_THREAD_UNRESPONSIVE, "Search thread became unresponsive.");
		///*
		if (deltaTime > 60 * 1000) {
			strcpy(info->status, "Restarting search thread...");
			auto native_handle = cuda_device_search_threads[index]->native_handle();
			cuda_device_search_threads[index]->detach();
			delete cuda_device_search_threads[index];
#if defined(_WIN32) || defined(_WIN64)
			TerminateThread(native_handle, 0);
#elif defined(_POSIX_THREADS)
			pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
			pthread_cancel(native_handle);
#endif
			cuda_device_search_threads[index] = new std::thread((lenTripcode == 10) 
														          ? Thread_SearchForDESTripcodesOnCUDADevice
															      : Thread_SearchForSHA1TripcodesOnCUDADevice,
															    &(CUDADeviceSearchThreadInfoArray[index]));
		}
		//*/
	}
	cuda_device_search_thread_info_array_spinlock.unlock();
#endif

#ifdef ENABLE_OPENCL
	opencl_device_search_thread_info_array_spinlock.lock();
	for (int32_t index = 0; index < numOpenCLDeviceSearchThreads; ++index) {
		struct OpenCLDeviceSearchThreadInfo *info = &openCLDeviceSearchThreadInfoArray[index];
		uint64_t  currentTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		uint64_t  deltaTime = currentTime - info->timeLastUpdated;
		//ERROR0(deltaTime > 1 * 60 * 1000, ERROR_SEARCH_THREAD_UNRESPONSIVE, "Search thread became unresponsive.");
		///*
		if (deltaTime > 60 * 1000) {
			// If we restart the search thread while the OpenCL kernel is running, amdocl64.dll may crash.
			ERROR0(!info->runChildProcess, ERROR_SEARCH_THREAD_UNRESPONSIVE, "Search thread became unresponsive.");

			strcpy(info->status, "[process] Restarting search thread...");
			// auto native_handle = opencl_device_search_threads[index]->native_handle();
			opencl_device_search_threads[index]->detach();
			delete opencl_device_search_threads[index];
#if defined(_WIN32) || defined(__CYGWIN__)
			// Boost.Processs is happy with none of these lines below.
#if 0
#if defined(_WIN32) || defined(__CYGWIN__)
			TerminateThread(native_handle, 0);
#elif defined(_POSIX_THREADS)
			pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
			pthread_cancel(native_handle);
#endif
#endif
			info->currentSpeed = 0;
			info->averageSpeed = 0;
			++info->numRestarts;
			opencl_device_search_threads[index] = new std::thread((lenTripcode == 10) 
																	       ? Thread_SearchForDESTripcodesOnOpenCLDevice
													                       : Thread_SearchForSHA1TripcodesOnOpenCLDevice,
																	   &(openCLDeviceSearchThreadInfoArray[index]));
#else
			info->currentSpeed = 0;
#endif
		}
		//*/
	}
	opencl_device_search_thread_info_array_spinlock.unlock();
#endif
}

void KeepSearchThreadsAlive()
{
#ifdef ENABLE_CUDA
	cuda_device_search_thread_info_array_spinlock.lock();
	for (int32_t index = 0; index < numCUDADeviceSearchThreads; ++index)
		CUDADeviceSearchThreadInfoArray[index].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
	cuda_device_search_thread_info_array_spinlock.unlock();
#endif

#ifdef ENABLE_OPENCL
	opencl_device_search_thread_info_array_spinlock.lock();
	for (int32_t index = 0; index < numOpenCLDeviceSearchThreads; ++index)
		openCLDeviceSearchThreadInfoArray[index].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
	opencl_device_search_thread_info_array_spinlock.unlock();
#endif
}

void PrintStatus(bool update_status = true)
{
	if (GetErrorState() || UpdateTerminationState())
		return;

	current_state_spinlock.lock();

	static char msg[MAX_NUM_LINES_STATUS_MSG][LEN_LINE_BUFFER_FOR_SCREEN];
	if (prevLineCount && !update_status && !options.redirection) {
	    for (int32_t i = 0; i < prevLineCount; ++i)
	        printf("%-79s\n", &(msg[i][0]));
	    reset_cursor_pos(-prevLineCount);
	    current_state_spinlock.unlock();
	    return;
	}

	int32_t lineCount = 0;

#define NEXT_LINE &(msg[lineCount++][0])

	sprintf(NEXT_LINE, "%-79s", "");
	sprintf(NEXT_LINE, "%-79s", "STATUS");
	sprintf(NEXT_LINE, "%-79s", "======");
	sprintf(NEXT_LINE, "  Performing a %s search on %s",
			(searchMode == SEARCH_MODE_FORWARD_MATCHING             ) ? "forward-matching"  :
			(searchMode == SEARCH_MODE_BACKWARD_MATCHING            ) ? "backward-matching" :
			(searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) ? "forward- and backward-matching" :
	                                                                    "flexible",
			(searchDevice == SEARCH_DEVICE_CPU) ? "CPU" :
			(searchDevice == SEARCH_DEVICE_GPU) ? "GPU(s)" :
	                                              "CPU and GPU(s)");
	if (minLenExpandedPattern != maxLenExpandedPattern) {
		sprintf(NEXT_LINE,
				"  for %d pattern%s (%d chunk%s) with %d to %d characters%s",
				numExpandedPatterns,
				(numExpandedPatterns == 1) ? "" : "s",
				numTripcodeChunk,
				(numTripcodeChunk == 1) ? "" : "s",
				minLenExpandedPattern,
				maxLenExpandedPattern,
				(searchDevice == SEARCH_DEVICE_CPU) ? "." : ":");
		
	} else {
		sprintf(NEXT_LINE,
				"  for %d pattern%s (%d chunk%s) with %d characters%s",
				numExpandedPatterns,
				(numExpandedPatterns == 1) ? "" : "s",
				numTripcodeChunk,
				(numTripcodeChunk == 1) ? "" : "s",
				minLenExpandedPattern,
				(searchDevice == SEARCH_DEVICE_CPU) ? "." : ":");
	}
#ifdef ENABLE_CUDA
	if (searchDevice != SEARCH_DEVICE_CPU && CUDADeviceSearchThreadInfoArray) {
		cuda_device_search_thread_info_array_spinlock.lock();
		if (numCUDADeviceSearchThreads == 1) {
			sprintf(NEXT_LINE, "      CUDA0:     %s", CUDADeviceSearchThreadInfoArray[0].status);
		} else {
			for (int32_t i = 0; i < numCUDADeviceSearchThreads; ++i)
				sprintf(NEXT_LINE, "      CUDA%d-%d:     %s", CUDADeviceSearchThreadInfoArray[i].CUDADeviceIndex, CUDADeviceSearchThreadInfoArray[i].subindex, CUDADeviceSearchThreadInfoArray[i].status);
		}
		cuda_device_search_thread_info_array_spinlock.unlock();
	}
#endif
#ifdef ENABLE_OPENCL
	if (searchDevice != SEARCH_DEVICE_CPU && openCLDeviceSearchThreadInfoArray) {
		opencl_device_search_thread_info_array_spinlock.lock();
		if (numOpenCLDeviceSearchThreads == 1) {
			sprintf(NEXT_LINE, "      OpenCL0:   %s", openCLDeviceSearchThreadInfoArray[0].status);
		} else {
			for (int32_t i = 0; i < numOpenCLDeviceSearchThreads; ++i) {
				if (openCLDeviceSearchThreadInfoArray[i].subindex < 0) {
					sprintf(NEXT_LINE, "      OpenCL%d:   %s",  openCLDeviceSearchThreadInfoArray[i].index, openCLDeviceSearchThreadInfoArray[i].status);
				} else {
					sprintf(NEXT_LINE, "      OpenCL%d-%d: %s", openCLDeviceSearchThreadInfoArray[i].index, openCLDeviceSearchThreadInfoArray[i].subindex, openCLDeviceSearchThreadInfoArray[i].status);
				}
			}
		}
		opencl_device_search_thread_info_array_spinlock.unlock();
	}
#endif

	double currentSpeed_childProcesses = 0;
	// double averageSpeed_childProcesses = 0;
	double totalNumGeneratedTripcodes_childProcesses = 0;
	uint32_t numDiscardedTripcodes_childProcesses = 0;
	// printf("numOpenCLDeviceSearchThreads = %d\n", numOpenCLDeviceSearchThreads);
#ifdef ENABLE_OPENCL
	if (openCLDeviceSearchThreadInfoArray && openCLRunChildProcesses) {
		opencl_device_search_thread_info_array_spinlock.lock();
		for (int32_t i = 0; i < numOpenCLDeviceSearchThreads; ++i) {
			// printf("deviceNo = %d\n", openCLDeviceSearchThreadInfoArray[i].deviceNo);
			if (!(openCLDeviceSearchThreadInfoArray[i].runChildProcess))
				continue;
			currentSpeed_childProcesses               += openCLDeviceSearchThreadInfoArray[i].currentSpeed;
			// averageSpeed_childProcesses               += openCLDeviceSearchThreadInfoArray[i].averageSpeed;
			totalNumGeneratedTripcodes_childProcesses += openCLDeviceSearchThreadInfoArray[i].totalNumGeneratedTripcodes;
			numDiscardedTripcodes_childProcesses      += openCLDeviceSearchThreadInfoArray[i].numDiscardedTripcodes;
		}
		opencl_device_search_thread_info_array_spinlock.unlock();
	}
#endif

	double averageSpeed;
	double averageSpeed_GPU;
	double averageSpeed_CPU;
	double timeForOneMatch;
	double actualMatchingProb;
	double matchingProbDiff;
	double invalidTripcodeRatio = (prevNumValidTripcodes + prevNumDiscardedTripcodes > 0)
			                            ? ((double)(prevNumDiscardedTripcodes) / (prevNumValidTripcodes + prevNumDiscardedTripcodes))
										: 0;
	if (totalTime > 0) {
		uint32_t remainingSeconds = (uint32_t)totalTime;
		uint32_t totalTimeDays    = remainingSeconds / (24 * 60 * 60); remainingSeconds -= totalTimeDays    * 24 * 60 * 60;
		uint32_t totalTimeHours   = remainingSeconds / (     60 * 60); remainingSeconds -= totalTimeHours        * 60 * 60;
		uint32_t totalTimeMinutes = remainingSeconds / (          60); remainingSeconds -= totalTimeMinutes           * 60;
		uint32_t totalTimeSeconds = remainingSeconds;
		
		msg[lineCount++][0] = '\0';
		sprintf(NEXT_LINE, "  %.3lfT tripcodes were generated in %dd %dh %dm %02ds at:",
				(prevTotalNumGeneratedTripcodes + totalNumGeneratedTripcodes_childProcesses) * 0.000000000001,
				totalTimeDays,
				totalTimeHours,
				totalTimeMinutes,
				totalTimeSeconds);
		sprintf(NEXT_LINE, "      %3.2lfM tripcode/s (current)", (currentSpeed_thisProcess + currentSpeed_childProcesses) / 1000000);
		if (searchDevice == SEARCH_DEVICE_GPU_AND_CPU) {
			sprintf(NEXT_LINE, "          GPU: %7.2lfM tripcode/s", (currentSpeed_thisProcess_GPU + currentSpeed_childProcesses) / 1000000);
			sprintf(NEXT_LINE, "          CPU: %7.2lfM tripcode/s", currentSpeed_CPU / 1000000);
		}
#ifdef DISPLAY_MAXIMUM_SPEED
		sprintf(NEXT_LINE, "      %3.2lfM tripcode/s (maximum)", maximumSpeed);
#endif
		// averageSpeed = prevTotalNumGeneratedTripcodes / totalTime + averageSpeed_childProcesses;
		// averageSpeed_GPU = prevTotalNumGeneratedTripcodes_GPU / totalTime + averageSpeed_childProcesses;
		averageSpeed     = (prevTotalNumGeneratedTripcodes + totalNumGeneratedTripcodes_childProcesses) / totalTime;
		averageSpeed_GPU = (prevTotalNumGeneratedTripcodes_GPU + totalNumGeneratedTripcodes_childProcesses) / totalTime;
		averageSpeed_CPU = prevTotalNumGeneratedTripcodes_CPU / totalTime;
		sprintf(NEXT_LINE, "      %3.2lfM tripcode/s (average)",  averageSpeed / 1000000);
		if (searchDevice == SEARCH_DEVICE_GPU_AND_CPU) {
			sprintf(NEXT_LINE, "          GPU: %7.2lfM tripcode/s", averageSpeed_GPU / 1000000);
			sprintf(NEXT_LINE, "          CPU: %7.2lfM tripcode/s", averageSpeed_CPU / 1000000);
		}
		
		timeForOneMatch = numAverageTrialsForOneMatch / averageSpeed;
		if (averageSpeed > 0 && !searchForSpecialPatternsOnCPU) {
			if (timeForOneMatch >= 100.0 * 365 * 24 * 60 * 60) {
				sprintf(NEXT_LINE, "  On average, it takes %.1lf centuries to find one match at this speed.", timeForOneMatch / (100.0 * 365 * 24 * 60 * 60));			
			} else if (timeForOneMatch >= 365.0 * 24 * 60 * 60) {
				sprintf(NEXT_LINE, "  On average, it takes %.1lf years to find one match at this speed.", timeForOneMatch / (365.0 * 24 * 60 * 60));			
			} else if (timeForOneMatch >= 30.4 * 24 * 60 * 60) {
				sprintf(NEXT_LINE, "  On average, it takes %.1lf months to find one match at this speed.", timeForOneMatch / (30.4 * 24 * 60 * 60));			
			} else if (timeForOneMatch >= 24 * 60 * 60) {
				sprintf(NEXT_LINE, "  On average, it takes %.1lf days to find one match at this speed.", timeForOneMatch / (24 * 60 * 60));			
			} else if (timeForOneMatch >= 60 * 60) {
				sprintf(NEXT_LINE, "  On average, it takes %.1lf hours to find one match at this speed.", timeForOneMatch / (60 * 60));			
			} else if (timeForOneMatch >= 60) {
				sprintf(NEXT_LINE, "  On average, it takes %.1lf minutes to find one match at this speed.", timeForOneMatch / 60);			
			} else {
				sprintf(NEXT_LINE, "  On average, it takes %.1lf seconds to find one match at this speed.", timeForOneMatch);			
			}
		}
		msg[lineCount++][0] = '\0';
		if (numValidTripcodes <= 0) {
			sprintf(NEXT_LINE, "  No matches were found yet.");
		} else {
			if (prevNumValidTripcodes > 0) {
				sprintf(NEXT_LINE, "  %u match%s found at %.2lf matches/h and %.2lfG tripcodes/match.",
						prevNumValidTripcodes,
						(prevNumValidTripcodes == 1) ? "" : "es",
						prevNumValidTripcodes / (totalTime / 3600),
						(double)(prevTotalNumGeneratedTripcodes + totalNumGeneratedTripcodes_childProcesses) / prevNumValidTripcodes * 0.000000001);
			}
			actualMatchingProb = (prevNumValidTripcodes + prevNumDiscardedTripcodes + numDiscardedTripcodes_childProcesses) / (prevTotalNumGeneratedTripcodes + totalNumGeneratedTripcodes_childProcesses);
			matchingProbDiff = (actualMatchingProb - matchingProb) / matchingProb;
#ifdef DEBUG_DISPLAY_MATCHING_PROBABILITY
			sprintf(NEXT_LINE, "  The theoretical matching probability is %0.20lf%%.", matchingProb);
#endif
			if (!searchForSpecialPatternsOnCPU) {
				if (matchingProbDiff > 0.01) {
					sprintf(NEXT_LINE, "  The actual matching probability is %.0f%% higher than expected.", matchingProbDiff * 100);
				} else if (matchingProbDiff < -0.01) {
					sprintf(NEXT_LINE, "  The actual matching probability is %.0f%% lower than expected.",
							-matchingProbDiff * 100);
				} else {
					sprintf(NEXT_LINE, "  The actual matching probability is about the same as expected.");
				}
			}
			if (prevNumValidTripcodes + prevNumDiscardedTripcodes > 0) {
				sprintf(NEXT_LINE, "  %.0f%% of matching tripcodes were invalid.",
						invalidTripcodeRatio * 100);
			}
		}
	}
	
	if (!options.redirection) {
		for (int32_t i = 0; i < lineCount; ++i)
			printf("%-79s\n", &(msg[i][0]));
		reset_cursor_pos(-lineCount);
		prevLineCount = lineCount;
	} else {
		if (totalTime > 0 && !searchForSpecialPatternsOnCPU) {
			printf("[status],%.0lf,%.0lf,%.0lf,%.0lf,%.0lf,%.1lf,%s%d%%,%.0lf,%u,%d,%.0lf,%.0lf,%u,%.0f%%\n",
			       totalTime,
				   currentSpeed_thisProcess     + currentSpeed_childProcesses,
				   currentSpeed_thisProcess_GPU + currentSpeed_childProcesses,
				   currentSpeed_CPU,
				   averageSpeed,
				   timeForOneMatch,
				   ((int32_t)(matchingProbDiff * 100) > 0) ? "+" : "", // All I want to do here is to avoid "-0%" and "+0%".
				    (int32_t)(matchingProbDiff * 100),
				   prevTotalNumGeneratedTripcodes + totalNumGeneratedTripcodes_childProcesses,
				   prevNumValidTripcodes,
				   FALSE,
				   averageSpeed_GPU,
				   averageSpeed_CPU,
				   prevNumDiscardedTripcodes,
				   invalidTripcodeRatio * 100);
		} else if (totalTime > 0) {
			printf("[status],%.0lf,%.0lf,%.0lf,%.0lf,%.0lf,-,-,%.0lf,%u,%d,%.0lf,%.0lf,%u,%.0f%%\n",
			       totalTime,
				   currentSpeed_thisProcess     + currentSpeed_childProcesses,
				   currentSpeed_thisProcess_GPU + currentSpeed_childProcesses,
				   currentSpeed_CPU,
				   averageSpeed,
				   prevTotalNumGeneratedTripcodes + totalNumGeneratedTripcodes_childProcesses,
				   prevNumValidTripcodes,
				   FALSE,
				   averageSpeed_GPU,
				   averageSpeed_CPU,
				   prevNumDiscardedTripcodes,
				   invalidTripcodeRatio * 100);
		}
		fflush(stdout);
	}
	
	current_state_spinlock.unlock();
#undef NEXT_LINE
}

#if defined(_WIN32) || defined(__CYGWIN__)

BOOL WINAPI ControlHandler(_In_  DWORD dwCtrlType)
{
	switch (dwCtrlType) {
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_SHUTDOWN_EVENT:
	case CTRL_LOGOFF_EVENT:
		SetTerminationState();
		while (TRUE)
			sleep_for_milliseconds(1000);
		return TRUE;
	default:
		return FALSE;
	}
}

#else

void control_handler(int s)
{
	SetTerminationState();
}

#endif

void InitProcess()
{
	hide_cursor();
#if defined(_WIN32) || defined(__CYGWIN__)
	SetConsoleCtrlHandler(ControlHandler, true);
#else
	struct sigaction sigint_handler;

	sigint_handler.sa_handler = control_handler;
	sigemptyset(&sigint_handler.sa_mask);
	sigint_handler.sa_flags = 0;

	sigaction(SIGINT, &sigint_handler, NULL);
#endif
}

#ifdef ENABLE_CUDA
void ListCUDADevices()
{
	int32_t i;
	cudaDeviceProp CUDADeviceProperties;
	
	cudaGetDeviceCount(&CUDADeviceCount);

	for (i = 0; i < CUDADeviceCount; ++i) {
		cudaGetDeviceProperties(&CUDADeviceProperties, i);
		printf("NVIDIA %s (CUDA)\n", CUDADeviceProperties.name); 
	}
}
#endif

#ifdef ENABLE_OPENCL
void CountOpenCLDevices()
{
    cl_int        errorCode;
    cl_uint       numPlatforms;
	cl_uint       deviceCount;
	cl_device_id *devices = NULL;

	openCLDeviceCount = 0;

	// Get a list of platforms
	errorCode = clGetPlatformIDs(0, NULL, &numPlatforms);
    if (errorCode != CL_SUCCESS || numPlatforms <= 0)
		return;
	cl_platform_id* platforms = (cl_platform_id*)malloc(sizeof(cl_platform_id) * numPlatforms);
	ERROR0(platforms == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
    errorCode = clGetPlatformIDs(numPlatforms, platforms, NULL);
    OPENCL_ERROR(errorCode);

	int32_t openCLDeviceIDArrayIndex = 0;
	for (int32_t pass = 0; pass <= 1; ++pass) {
		for (cl_uint platformIndex = 0; platformIndex < numPlatforms; ++platformIndex) {
			// Skip CUDA devices.
			char platformVendor[LEN_LINE_BUFFER_FOR_SCREEN];
			errorCode = clGetPlatformInfo(platforms[platformIndex], CL_PLATFORM_VENDOR, sizeof(platformVendor), platformVendor, NULL);
			// OPENCL_ERROR(errorCode);
			if (errorCode != CL_SUCCESS)
				continue;
			if (   (strcmp(platformVendor, OPENCL_VENDOR_NVIDIA) == 0 && !options.useOpenCLForCUDADevices)
				||  strcmp(platformVendor, OPENCL_VENDOR_INTEL ) == 0                                     )
				continue;
		
			// Get a list of devices on the platform.
			errorCode = clGetDeviceIDs(platforms[platformIndex], CL_DEVICE_TYPE_ALL, 0, NULL, &deviceCount);
			// OPENCL_ERROR(errorCode);
			// if (errorCode == CL_DEVICE_NOT_FOUND)
			//	continue;
			if (errorCode != CL_SUCCESS)
				continue;
			devices = (cl_device_id*)malloc(sizeof(cl_device_id) * deviceCount);
			ERROR0(devices == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
			errorCode = clGetDeviceIDs(platforms[platformIndex], CL_DEVICE_TYPE_GPU | CL_DEVICE_TYPE_ACCELERATOR, deviceCount, devices, &deviceCount);
			if (errorCode != CL_DEVICE_NOT_FOUND) {
				OPENCL_ERROR(errorCode);
				for (cl_uint deviceIndex = 0; deviceIndex < deviceCount; ++deviceIndex) {
					if (pass == 0) {
						++openCLDeviceCount;
					} else {
						openCLDeviceIDArray[openCLDeviceIDArrayIndex++] = devices[deviceIndex];
					}
				}
			}
			free(devices);
		}
		if (pass == 0) {
			openCLDeviceIDArray = (cl_device_id *)malloc(sizeof(cl_device_id) * openCLDeviceCount);
			ERROR0(openCLDeviceIDArray == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
		}
	}

    free(platforms);
}

void ListOpenCLDevices()
{
	char    deviceVendor[LEN_LINE_BUFFER_FOR_SCREEN];
	char    deviceName  [LEN_LINE_BUFFER_FOR_SCREEN];
	cl_uint numComputeUnits;

	CountOpenCLDevices();

	for(int32_t deviceIndex = 0; deviceIndex < openCLDeviceCount; ++deviceIndex) {  
		OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[deviceIndex], CL_DEVICE_VENDOR,            sizeof(deviceVendor),    &deviceVendor,    NULL));
		OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[deviceIndex], CL_DEVICE_NAME,              sizeof(deviceName),      &deviceName,      NULL));
		OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[deviceIndex], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(numComputeUnits), &numComputeUnits, NULL));
		// printf("%d: ", CUDADeviceCount + deviceIndex);
		if (strcmp(deviceVendor, OPENCL_VENDOR_AMD) == 0) {
			printf("AMD ");
		} else if (strcmp(deviceVendor, OPENCL_VENDOR_INTEL) == 0) {
			// Do not print anything.
		} else if (strcmp(deviceVendor, OPENCL_VENDOR_NVIDIA) == 0) {
			printf("NVIDIA ");
		} else {
			printf("%s ", deviceVendor);
		}
		const char *productName = GetProductNameForOpenCLDevice(deviceVendor, deviceName, numComputeUnits);
		if (productName) {
			printf("%s", productName);
		} else {
			printf("%s", deviceName);
		}
		printf(" (OpenCL)\n");
	}
}
#endif

void ListGPUsAndExit()
{
#ifdef ENABLE_CUDA
	if (!options.useOpenCLForCUDADevices)
		ListCUDADevices();
#endif
#ifdef ENABLE_OPENCL
	ListOpenCLDevices();
#endif
	exit(0);
}

void InitSearchDevices(BOOL displayDeviceInformation)
{
#ifdef ENABLE_CUDA
	if (options.useOpenCLForCUDADevices) {
		CUDADeviceCount = 0;
	} else {
		cudaGetDeviceCount(&CUDADeviceCount);
	}
#endif
#ifdef ENABLE_OPENCL
	CountOpenCLDevices();
#endif
#if defined(ENABLE_CUDA) && defined(ENABLE_OPENCL)
	ERROR0(options.GPUIndex != GPU_INDEX_ALL
		&& (options.GPUIndex < 0 || CUDADeviceCount + openCLDeviceCount <= options.GPUIndex),
		ERROR_INVALID_OPTION,
		"An invalid device was specified.");
	if (options.searchDevice == SEARCH_DEVICE_NIL) {
		searchDevice = (CUDADeviceCount <= 0 && openCLDeviceCount <= 0) ? (SEARCH_DEVICE_CPU) : (SEARCH_DEVICE_GPU);
	}
	else {
		searchDevice = options.searchDevice;
	}
#elif defined(ENABLE_CUDA)
	ERROR0(options.GPUIndex != GPU_INDEX_ALL
		&& (options.GPUIndex < 0 || CUDADeviceCount <= options.GPUIndex),
		ERROR_INVALID_OPTION,
		"An invalid device was specified.");
	if (options.searchDevice == SEARCH_DEVICE_NIL) {
		searchDevice = (CUDADeviceCount <= 0) ? (SEARCH_DEVICE_CPU) : (SEARCH_DEVICE_GPU);
	}
	else {
		searchDevice = options.searchDevice;
	}
#elif defined(ENABLE_OPENCL)
	ERROR0(options.GPUIndex != GPU_INDEX_ALL
		&& (options.GPUIndex < 0 || openCLDeviceCount <= options.GPUIndex),
		ERROR_INVALID_OPTION,
		"An invalid device was specified.");
	if (options.searchDevice == SEARCH_DEVICE_NIL) {
		searchDevice = (openCLDeviceCount <= 0) ? (SEARCH_DEVICE_CPU) : (SEARCH_DEVICE_GPU);
	}
	else {
		searchDevice = options.searchDevice;
	}
#else
	if (options.searchDevice == SEARCH_DEVICE_NIL) {
		searchDevice = SEARCH_DEVICE_CPU;
	}
	else {
		searchDevice = options.searchDevice;
	}
#endif
#ifdef DEBUG_USE_CPU_ONLY
	searchDevice = SEARCH_DEVICE_CPU;
#endif
	
#if defined(ENABLE_CUDA) && defined(ENABLE_OPENCL)
	ERROR0((searchDevice == SEARCH_DEVICE_GPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU) && CUDADeviceCount <= 0 && openCLDeviceCount <= 0,
		ERROR_INVALID_OPTION, "There is no GPU.");
#elif defined(ENABLE_CUDA)
	ERROR0((searchDevice == SEARCH_DEVICE_GPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU) && CUDADeviceCount <= 0,
		ERROR_INVALID_OPTION, "There is no GPU.");
#elif defined(ENABLE_OPENCL)
	ERROR0((searchDevice == SEARCH_DEVICE_GPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU) && openCLDeviceCount <= 0,
		ERROR_INVALID_OPTION, "There is no GPU.");
#else
	ERROR0(searchDevice == SEARCH_DEVICE_GPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU,
		ERROR_INVALID_OPTION, "There is no GPU.");
#endif

#ifdef ENABLE_CUDA
	numCUDADeviceSearchThreads = 0;
	if (   (searchDevice == SEARCH_DEVICE_GPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU)
		&& CUDADeviceCount > 0
		&& !options.useOpenCLForCUDADevices
		&& (options.GPUIndex == GPU_INDEX_ALL || options.GPUIndex < CUDADeviceCount)) {
		cudaDeviceProp CUDADeviceProperties;

		if (displayDeviceInformation && CUDADeviceCount > 1 && options.GPUIndex == GPU_INDEX_ALL) {
			printf("CUDA DEVICES\n");
			printf("============\n");
			printf(        "  CUDA Device Count:        %d\n\n", CUDADeviceCount);
		} else if (displayDeviceInformation) {
			printf("CUDA DEVICE\n");
			printf("===========\n");
		}
		for (int i = ((options.GPUIndex == GPU_INDEX_ALL) ? 0               :  options.GPUIndex     );
		     i < ((options.GPUIndex == GPU_INDEX_ALL) ? CUDADeviceCount : (options.GPUIndex + 1));
			 ++i) {
			if (displayDeviceInformation) {
				cudaGetDeviceProperties(&CUDADeviceProperties, i);
				printf(    "  Device No.:               %d\n",      i);
				printf(    "  Device Name:              %s\n",      CUDADeviceProperties.name);
				printf(    "  Multiprocessor Count:     %d\n",      CUDADeviceProperties.multiProcessorCount);
				printf(    "  Clock Rate:               %.0fMHz\n", CUDADeviceProperties.clockRate * 1e-3f);
				printf(    "  Compute Capability:       %d.%d\n",   CUDADeviceProperties.major, CUDADeviceProperties.minor);
				printf(    "  Compute Mode:             %s\n",
					   (CUDADeviceProperties.computeMode == cudaComputeModeDefault         ) ? "cudaComputeModeDefault"          :
					   (CUDADeviceProperties.computeMode == cudaComputeModeExclusive       ) ? "cudaComputeModeExclusive"        :
					   (CUDADeviceProperties.computeMode == cudaComputeModeProhibited      ) ? "cudaComputeModeProhibited"       :
					   (CUDADeviceProperties.computeMode == cudaComputeModeExclusiveProcess) ? "cudaComputeModeExclusiveProcess" :
					                                                                           "(unknown)"                        );
				printf("\n");
			}
			numCUDADeviceSearchThreads += CUDA_NUM_THREADS_PER_DEVICE;
		}
	}
#endif

#ifdef ENABLE_OPENCL
	numOpenCLDeviceSearchThreads = 0;
	if ((searchDevice == SEARCH_DEVICE_GPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU)
		&& openCLDeviceCount > 0
		&& (options.GPUIndex == GPU_INDEX_ALL || CUDADeviceCount <= options.GPUIndex)) {

		if (displayDeviceInformation && openCLDeviceCount > 1 && options.GPUIndex == GPU_INDEX_ALL) {
			printf("OPENCL DEVICES\n");
			printf("==============\n");
			printf(        "  OpenCL Device Count:      %d\n\n", openCLDeviceCount);
		} else if (displayDeviceInformation) {
			printf("OPENCL DEVICE\n");
			printf("=============\n");
		}
		openCLRunChildProcesses =    (   options.openCLRunChildProcesses
		                              && (openCLDeviceCount > 1)
			                          && (options.GPUIndex == GPU_INDEX_ALL))
								  || options.openCLNumProcesses > 1;

		// printf("openCLRunChildProcesses = %d\n", openCLRunChildProcesses);
		for (int i = ((options.GPUIndex == GPU_INDEX_ALL) ? CUDADeviceCount                     : (options.GPUIndex    ));
		     i < ((options.GPUIndex == GPU_INDEX_ALL) ? CUDADeviceCount + openCLDeviceCount : (options.GPUIndex + 1));
			 ++i) {
			int32_t openCLDeviceIndex = i - CUDADeviceCount;
			char deviceVendor [LEN_LINE_BUFFER_FOR_SCREEN];
			char deviceName   [LEN_LINE_BUFFER_FOR_SCREEN];
			char deviceVersion[LEN_LINE_BUFFER_FOR_SCREEN];
			char driverVersion[LEN_LINE_BUFFER_FOR_SCREEN];
			cl_ulong globalMemorySize;
			cl_uint  clockFrequency;
			cl_uint  numComputeUnits;
			size_t maxWorkGroupSize;
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIndex], CL_DEVICE_VENDOR,              sizeof(deviceVendor),     &deviceVendor,     NULL));
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIndex], CL_DEVICE_NAME,                sizeof(deviceName),       &deviceName,       NULL));
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIndex], CL_DEVICE_VERSION,             sizeof(deviceVersion),    &deviceVersion,    NULL));
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIndex], CL_DRIVER_VERSION,             sizeof(driverVersion),    &driverVersion,    NULL));
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIndex], CL_DEVICE_GLOBAL_MEM_SIZE,     sizeof(globalMemorySize), &globalMemorySize, NULL));
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIndex], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(clockFrequency),   &clockFrequency,   NULL));
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIndex], CL_DEVICE_MAX_COMPUTE_UNITS,   sizeof(numComputeUnits),  &numComputeUnits,  NULL));
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIndex], CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(maxWorkGroupSize), &maxWorkGroupSize, NULL));
			const char *productName = GetProductNameForOpenCLDevice(deviceVendor, deviceName, numComputeUnits);
			if (displayDeviceInformation) {
				printf(    "  Vendor:                   %s\n",        deviceVendor);
				if (productName) {
					printf(    "  Name:                     %s (%s)\n", deviceName, productName);
				} else {
					printf(    "  Name:                     %s\n",      deviceName);
				}
				printf(    "  Number of Compute Units:  %d\n",        (int32_t)numComputeUnits);
				printf(    "  Clock Frequency:          %dMHz\n",     (int32_t)clockFrequency);
				printf(    "  Global Memory Size:       %dM bytes\n", (int32_t)(globalMemorySize / 1024 / 1024));
				printf(    "  Max. Work Group Size:     %d\n",        (int32_t)maxWorkGroupSize);
				printf(    "  Version:                  %s\n",        deviceVersion);
				printf(    "  Driver Version:           %s\n",        driverVersion);
				printf("\n");
			}
			if (openCLRunChildProcesses) {
				numOpenCLDeviceSearchThreads += options.openCLNumProcesses;
			} else {
				numOpenCLDeviceSearchThreads += options.openCLNumThreads;
			}
		}
	}
#endif

	numCPUSearchThreads = 0;
	if (searchDevice == SEARCH_DEVICE_CPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU) {
#ifdef DEBUG_ONE_CPU_SEARCH_THREAD
		numCPUSearchThreads = 1;
#else
		numCPUSearchThreads = std::thread::hardware_concurrency();
		if (options.numCPUSearchThreads == NUM_CPU_SEARCH_THREADS_NIL) { 
			if (searchDevice == SEARCH_DEVICE_GPU_AND_CPU)
				numCPUSearchThreads = (numCPUSearchThreads > numCUDADeviceSearchThreads + numOpenCLDeviceSearchThreads)
										  ? (numCPUSearchThreads - numCUDADeviceSearchThreads - numOpenCLDeviceSearchThreads)
										  : 0;
		} else {
			numCPUSearchThreads = (options.numCPUSearchThreads < numCPUSearchThreads) ? options.numCPUSearchThreads : numCPUSearchThreads;
		}
#endif
		if (searchDevice == SEARCH_DEVICE_GPU_AND_CPU && numCPUSearchThreads <= 0) {
			searchDevice = SEARCH_DEVICE_GPU;
		} else 	if (displayDeviceInformation) {
			printf("CPU\n");
			printf("===\n");
#if defined(_MSC_VER) || defined(__CYGWIN__)
			int32_t results[4];
			__cpuid(results, 1);
#ifdef USE_YASM
			if (IsCPUBasedOnNehalemMicroarchitecture()) {
				printf("  Processor Info:           0x%06x (Nehalem)\n", results[0]);
			} else {
				printf("  Processor Info:           0x%06x\n", results[0]);
			}
#else
			printf("  Processor Info:           0x%06x\n", results[0]);
#endif
#endif
			printf("  Number of Logical Cores:  %d\n", std::thread::hardware_concurrency());
			printf("  Number of Search Threads: %d\n", numCPUSearchThreads);
			printf("\n");
		}
	}
}

#include <boost/predef.h>
#if BOOST_OS_MACOS
#include <mach-o/dyld.h>
#elif BOOST_OS_BSD
#include <sys/sysctl.h>
#endif

void ObtainOptions(int32_t argCount, char **arguments)
{
	int32_t i;
	
	// Get the application path and directory.
#if defined(_MSC_VER)
	_fullpath(applicationPath, arguments[0], sizeof(applicationPath));
#elif BOOST_OS_LINUX
	size_t len = readlink("/proc/self/exe", applicationPath, sizeof(applicationPath));
	ASSERT(0 < len && len < sizeof(applicationPath));
#elif BOOST_OS_MACOS
	uint32_t size = sizeof(applicationPath);
	ASSERT(_NSGetExecutablePath(applicationPath, &size) == 0);
#elif BOOST_OS_BSD
	int mib[4] = {0};
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;
	size_t size = sizeof(applicationPath);
	ASSERT(sysctl(mib, 4, applicationPath, &size, NULL, 0) == 0);
#elif BOOST_OS_SOLARIS
	ASSERT(realpath(getexecname(), applicationPath));
#else
	strncpy(applicationPath, arguments[0], sizeof(applicationPath));
#endif
	strcpy(applicationDirectory, applicationPath);
	for (i = strlen(applicationPath) - 1; i > 0; --i) {
		if (applicationDirectory[i] == '\\' || applicationDirectory[i] == '/')
			break;
	}
	if (i < 0)
		i = 0;
	applicationDirectory[i] = '\0';
#if FALSE
	printf("arguments[0]         = \'%s\'\n", arguments[0]);
	printf("applicationPath      = \'%s\'\n", applicationPath);
	printf("applicationDirectory = \'%s\'\n", applicationDirectory);
#endif

	// Set default values if necessary.	
	strncpy(tripcodeFilePath, DEFAULT_NAME_TRIPCODE_FILE, sizeof(tripcodeFilePath));

	for (int32_t indexArg = 1; indexArg < argCount; ++indexArg) {
		if (strcmp(arguments[indexArg], "-o") == 0 && indexArg + 1 < argCount) {
			++indexArg;
			ERROR1(strlen(arguments[indexArg]) + 1 > sizeof(tripcodeFilePath),
			       ERROR_TRIPCODE_FILE,
			       "The path of the tripcode file `%s' is too long.",
			       arguments[indexArg]);
			strcpy(tripcodeFilePath, arguments[indexArg]);

		} else if (strcmp(arguments[indexArg], "-f") == 0 && indexArg + 1 < argCount) {
			++indexArg;
			ERROR1(strlen(arguments[indexArg]) > MAX_LEN_FILE_PATH,
			       ERROR_PATTERN_FILE,
			       "The path of the pattern file `%s' is too long.",
			       arguments[indexArg]);
			ERROR0(numPatternFiles >= MAX_NUM_PATTERN_FILES, ERROR_PATTERN_FILE, "Too many pattern files were specified.");
			strcpy(patternFilePathArray[numPatternFiles++], arguments[indexArg]);

		} else if (strcmp(arguments[indexArg], "-d") == 0 && indexArg + 1 < argCount) {
			options.GPUIndex = atoi(arguments[++indexArg]);

#ifdef ENABLE_CUDA
		} else if (strcmp(arguments[indexArg], "-x") == 0 && indexArg + 1 < argCount) {
			options.CUDANumBlocksPerSM = atoi(arguments[++indexArg]);
			ERROR1(options.CUDANumBlocksPerSM < CUDA_MIN_NUM_BLOCKS_PER_SM,
			       ERROR_INVALID_OPTION,
				   "The number of blocks per SM must be at least %d.", CUDA_MIN_NUM_BLOCKS_PER_SM);
			ERROR1(options.CUDANumBlocksPerSM > CUDA_MAX_NUM_BLOCKS_PER_SM,
			       ERROR_INVALID_OPTION,
				   "The number of blocks per SM cannot exceed %d.",    CUDA_MAX_NUM_BLOCKS_PER_SM);
#endif

#ifdef ENABLE_OPENCL
		} else if (strcmp(arguments[indexArg], "-y") == 0 && indexArg + 1 < argCount) {
			options.openCLNumWorkItemsPerCU = atoi(arguments[++indexArg]);
			ERROR1(options.openCLNumWorkItemsPerCU < OPENCL_MIN_NUM_WORK_ITEMS_PER_CU,
			       ERROR_INVALID_OPTION,
				   "The number of work items per CU must be at least %d.", OPENCL_MIN_NUM_WORK_ITEMS_PER_CU);
			ERROR1(options.openCLNumWorkItemsPerCU > OPENCL_MAX_NUM_WORK_ITEMS_PER_CU,
			       ERROR_INVALID_OPTION,
				   "The number of work items per CU cannot exceed %d.", OPENCL_MAX_NUM_WORK_ITEMS_PER_CU);

		} else if (strcmp(arguments[indexArg], "-z") == 0 && indexArg + 1 < argCount) {
			options.openCLNumWorkItemsPerWG = atoi(arguments[++indexArg]);
			ERROR1(options.openCLNumWorkItemsPerWG < OPENCL_MIN_NUM_WORK_ITEMS_PER_WG,
			       ERROR_INVALID_OPTION,
				   "The number of work items per WG must be at least %d.", OPENCL_MIN_NUM_WORK_ITEMS_PER_WG);
			ERROR1(options.openCLNumWorkItemsPerWG > OPENCL_MAX_NUM_WORK_ITEMS_PER_WG,
			       ERROR_INVALID_OPTION,
				   "The number of work items per WG cannot exceed %d.",    OPENCL_MAX_NUM_WORK_ITEMS_PER_WG);
			ERROR0(options.openCLNumWorkItemsPerWG % 8 != 0,
			       ERROR_INVALID_OPTION,
				   "The number of work items per WG must be a multiple of 8.");

		} else if (strcmp(arguments[indexArg], "-a") == 0 && indexArg + 1 < argCount) {
			options.openCLNumThreads = atoi(arguments[++indexArg]);
			ERROR1(options.openCLNumThreads < OPENCL_MIN_NUM_THREADS_PER_AMD_GPU,
			       ERROR_INVALID_OPTION,
				   "The number of threads per AMD GPU must be at least %d.", OPENCL_MIN_NUM_THREADS_PER_AMD_GPU);
			ERROR1(options.openCLNumThreads > OPENCL_MAX_NUM_THREADS_PER_AMD_GPU,
			       ERROR_INVALID_OPTION,
				   "The number of threads per AMD GPU cannot exceed %d.",    OPENCL_MAX_NUM_THREADS_PER_AMD_GPU);


		} else if (strcmp(arguments[indexArg], "-b") == 0 && indexArg + 1 < argCount) {
			options.openCLNumProcesses = atoi(arguments[++indexArg]);
			ERROR1(options.openCLNumProcesses < OPENCL_MIN_NUM_PROCESSES_PER_AMD_GPU,
			       ERROR_INVALID_OPTION,
				   "The number of processes per AMD GPU must be at least %d.", OPENCL_MIN_NUM_PROCESSES_PER_AMD_GPU);
			ERROR1(options.openCLNumProcesses > OPENCL_MAX_NUM_PROCESSES_PER_AMD_GPU,
			       ERROR_INVALID_OPTION,
				   "The number of processes per AMD GPU cannot exceed %d.",    OPENCL_MAX_NUM_PROCESSES_PER_AMD_GPU);
#endif

		} else if (strcmp(arguments[indexArg], "-l") == 0 && indexArg + 1 < argCount) {
			lenTripcode    = atoi(arguments[++indexArg]);
			lenTripcodeKey = lenTripcode;
			ERROR0(lenTripcode != 10 && lenTripcode != 12,
			       ERROR_INVALID_OPTION,
			       "The length of tripcodes must be either 10 or 12.");

		} else if (strcmp(arguments[indexArg], "-b") == 0) {
			options.beepWhenNewTripcodeIsFound = TRUE;

		} else if (strcmp(arguments[indexArg], "-i") == 0) {
			options.outputInvalidTripcode = TRUE;

		} else if (strcmp(arguments[indexArg], "-w") == 0) {
			options.warnSpeedDrop= TRUE;

		} else if (strcmp(arguments[indexArg], "-n") == 0) {
			options.testNewCode = TRUE;

		} else if (strcmp(arguments[indexArg], "-c") == 0) {
			options.searchDevice = (options.searchDevice == SEARCH_DEVICE_NIL ) ? (SEARCH_DEVICE_CPU)          :
			                       (options.searchDevice == SEARCH_DEVICE_GPU) ? (SEARCH_DEVICE_GPU_AND_CPU) :
			                                                                      (options.searchDevice);

		} else if (strcmp(arguments[indexArg], "-g") == 0) {
			options.searchDevice = (options.searchDevice == SEARCH_DEVICE_NIL)  ? (SEARCH_DEVICE_GPU)         :
			                       (options.searchDevice == SEARCH_DEVICE_CPU)  ? (SEARCH_DEVICE_GPU_AND_CPU) :
			                                                                      (options.searchDevice);

		} else if (strcmp(arguments[indexArg], "-t") == 0 && indexArg + 1 < argCount) {
			options.numCPUSearchThreads = atoi(arguments[++indexArg]);
			ERROR0(options.numCPUSearchThreads <= 0,
			       ERROR_INVALID_OPTION,
			       "The number of CPU search threads must be at least 1.");

		} else if (strcmp(arguments[indexArg], "--output-for-redirection") == 0) {
			options.redirection = TRUE;

		} else if (strcmp(arguments[indexArg], "-e") == 0 && indexArg + 1 < argCount) {
			pause_event.open_or_create(arguments[++indexArg]);

		} else if (strcmp(arguments[indexArg], "-E") == 0 && indexArg + 1 < argCount) {
			termination_event.open_or_create(arguments[++indexArg]);

		} else if (strcmp(arguments[indexArg], "--use-one-byte-characters-for-keys") == 0) {
			options.useOneByteCharactersForKeys = TRUE;

		} else if (strcmp(arguments[indexArg], "--search-for-hiseki-on-cpu") == 0) {
			options.searchForHisekiOnCPU = TRUE;

		} else if (strcmp(arguments[indexArg], "--search-for-kakuhi-on-cpu") == 0) {
			options.searchForKakuhiOnCPU = TRUE;

		} else if (strcmp(arguments[indexArg], "--search-for-kaibun-on-cpu") == 0) {
			options.searchForKaibunOnCPU = TRUE;

		} else if (strcmp(arguments[indexArg], "--search-for-kagami-on-cpu") == 0) {
			options.searchForKagamiOnCPU = TRUE;

		} else if (strcmp(arguments[indexArg], "--search-for-yamabiko-on-cpu") == 0) {
			options.searchForYamabikoOnCPU = TRUE;

		} else if (strcmp(arguments[indexArg], "--search-for-souren-on-cpu") == 0) {
			options.searchForSourenOnCPU = TRUE;
			
#if defined(ENABLE_CUDA) && defined(ENABLE_OPENCL)
		} else if (strcmp(arguments[indexArg], "--use-opencl-for-cuda-devices") == 0) {
			options.useOpenCLForCUDADevices = TRUE;
#endif

		} else if (strcmp(arguments[indexArg], "--disable-avx") == 0) {
			options.isAVXEnabled = FALSE;

		} else if (strcmp(arguments[indexArg], "--disable-avx2") == 0) {
			options.isAVX2Enabled = FALSE;

		} else if (strcmp(arguments[indexArg], "--use-one-byte-characters-for-keys") == 0) {
			options.useOnlyASCIICharactersForKeys = FALSE;
			options.useOneByteCharactersForKeys = TRUE;

		} else if (strcmp(arguments[indexArg], "--use-ascii-characters-for-keys") == 0) {
			options.useOnlyASCIICharactersForKeys = TRUE;
			options.useOneByteCharactersForKeys = TRUE;

		} else if (strcmp(arguments[indexArg], "--use-one-and-two-byte-characters-for-keys") == 0) {
			options.useOneByteCharactersForKeys = FALSE;
			options.useOnlyASCIICharactersForKeys = FALSE;

		} else if (strcmp(arguments[indexArg], "--maximize-key-space") == 0) {
			options.useOneByteCharactersForKeys = FALSE;
			options.useOnlyASCIICharactersForKeys = FALSE;
			options.maximizeKeySpace = TRUE;

		} else if (strcmp(arguments[indexArg], "--disable-tripcode-checks") == 0) {
			options.checkTripcodes = FALSE;

#if defined(ENABLE_OPENCL)
		} else if (strcmp(arguments[indexArg], "--disable-gcn-assembler") == 0) {
			options.enableGCNAssembler = FALSE;
#endif

		} else if (   strcmp(arguments[indexArg], "--display-device-information") == 0
			       || strcmp(arguments[indexArg], "--list-expanded-patterns"    ) == 0
				   || strcmp(arguments[indexArg], "--gpu-list"                  ) == 0) {
			// Ignore the option.

		} else {
			ERROR0(TRUE, ERROR_INVALID_OPTION, "An invalid option was specified.");
		}
	}

	if (numPatternFiles <= 0) {
		strcpy(patternFilePathArray[0], DEFAULT_NAME_PATTERN_FILE);
		numPatternFiles = 1;
	}
}

void ProcessValidTripcodePair(unsigned char *tripcode, unsigned char *key)
{
	ASSERT(lenTripcode    == 10 || lenTripcode    == 12);
	ASSERT(lenTripcodeKey == 10 || lenTripcodeKey == 12);
	
	process_tripcode_pair_spinlock.lock();
	if (!options.redirection) {
#ifdef ENGLISH_VERSION
		fprintf(tripcodeFile, "!");
#else
		fprintf(tripcodeFile, "%c%c", 0x81, 0x9f);
#endif
		for (int32_t i = 0; i < lenTripcode; ++i)
			fprintf(tripcodeFile, "%c", tripcode[i]);
		fprintf(tripcodeFile, " #");
		for (int32_t i = 0; i < lenTripcodeKey; ++i)
			fprintf(tripcodeFile, "%c", key[i]);
		fprintf(tripcodeFile, " (");
		for (int32_t i = 0; i < lenTripcodeKey; ++i) {
			fprintf(tripcodeFile, "%02X", key[i]);
			if (i + 1 < lenTripcodeKey)
				fprintf(tripcodeFile, " ");
		}
		fprintf(tripcodeFile, ")\n");
		fflush(tripcodeFile);
	}  

	if (!options.redirection && !UpdateTerminationState() && !GetErrorState()) {
#ifdef ENGLISH_VERSION
		printf("  !");
#else
		printf("  %c%c", 0x81, 0x9f);
#endif
		for (int32_t i = 0; i < lenTripcode; ++i)
			printf("%c", tripcode[i]);
		printf(" #");
		for (int32_t i = 0; i < lenTripcodeKey; ++i)
			printf("%c", key[i]);
		printf(" (");
		for (int32_t i = 0; i < lenTripcodeKey; ++i) {
			printf("%02X", key[i]);
			if (i + 1 < lenTripcodeKey)
				printf(" ");
		}
		printf(")");
		for (int32_t i = 4 + lenTripcode + 2 + lenTripcodeKey + 2 + lenTripcodeKey * 3;
			i < SCREEN_WIDTH - 1;
			++i) {
			printf(" ");
		}
		printf("\n");
	} else if (options.redirection) {
		printf("[tripcode],%c%c", 0x81, 0x9f);
		for (int32_t i = 0; i < lenTripcode; ++i)
			printf("%c", tripcode[i]);
		printf(",#");
		for (int32_t i = 0; i < lenTripcodeKey; ++i)
			printf("%c", key[i]);
		printf(",(");
		for (int32_t i = 0; i < lenTripcodeKey; ++i) {
			printf("%02X", key[i]);
			if (i + 1 < lenTripcodeKey)
				printf(" ");
		}
		printf(")\n");
	}
	fflush(stdout);
	process_tripcode_pair_spinlock.unlock();

	current_state_spinlock.lock();
	++numValidTripcodes;
	current_state_spinlock.unlock();

	if (!options.redirection)
		PrintStatus(false);
	if (!options.redirection && options.beepWhenNewTripcodeIsFound)
		printf("\a");
}

void ProcessInvalidTripcodePair(unsigned char *tripcode, unsigned char *key)
{
	process_tripcode_pair_spinlock.lock();
	if (options.outputInvalidTripcode && !options.redirection && !UpdateTerminationState() && !GetErrorState()) {
#ifdef ENGLISH_VERSION
		fprintf(tripcodeFile, "!");
#else
		fprintf(tripcodeFile, "%c%c", 0x81, 0x9f);
#endif
		for (int32_t i = 0; i < lenTripcode; ++i)
			fprintf(tripcodeFile, "%c", tripcode[i]);
		fprintf(tripcodeFile, "  ");
		for (int32_t i = 0; i < lenTripcodeKey; ++i)
			fprintf(tripcodeFile, " ");
		fprintf(tripcodeFile, " (");
		for (int32_t i = 0; i < lenTripcodeKey; ++i) {
			fprintf(tripcodeFile, "%02X", key[i]);
			if (i + 1 < lenTripcodeKey)
				fprintf(tripcodeFile, " ");
		}
		fprintf(tripcodeFile, ")\n");
		fflush(tripcodeFile);

#ifdef ENGLISH_VERSION
		printf("  !");
#else
		printf("  %c%c", 0x81, 0x9f);
#endif
		for (int32_t i = 0; i < lenTripcode; ++i)
			printf("%c", tripcode[i]);
		printf("  ");
		for (int32_t i = 0; i < lenTripcodeKey; ++i)
			printf(" ");
		printf(" (");
		for (int32_t i = 0; i < lenTripcodeKey; ++i) {
			printf("%02X", key[i]);
			if (i + 1 < lenTripcodeKey)
				printf(" ");
		}
		printf(")");
		for (int32_t i = 4 + lenTripcode + 2 + lenTripcodeKey + 2 + lenTripcodeKey * 3;
			i < SCREEN_WIDTH - 1;
			++i) {
			printf(" ");
		}
		printf("\n");
		fflush(stdout);
	}
	process_tripcode_pair_spinlock.unlock();

	current_state_spinlock.lock();
	++numDiscardedTripcodes;
	current_state_spinlock.unlock();

	if (options.outputInvalidTripcode && !options.redirection && !UpdateTerminationState() && !GetErrorState())
		PrintStatus(false);
}

void OpenTripcodeFile()
{
	tripcodeFile = fopen(tripcodeFilePath, "a");
	ERROR0(tripcodeFilePath == NULL, ERROR_TRIPCODE_FILE, "The output file cannot be opened.");
}

void AddToNumGeneratedTripcodesByCPU(uint32_t num)
{
	num_generated_tripcodes_spinlock.lock();
	numGeneratedTripcodes_CPU += num;
	if (numGeneratedTripcodes_CPU >= 1000000) {
		numGeneratedTripcodesByCPUInMillions += numGeneratedTripcodes_CPU / 1000000;
		numGeneratedTripcodes_CPU           %= 1000000;
	}
	num_generated_tripcodes_spinlock.unlock();
}

void AddToNumGeneratedTripcodesByGPU(uint32_t num)
{
	num_generated_tripcodes_spinlock.lock();
	numGeneratedTripcodes_GPU += num;
	if (numGeneratedTripcodes_GPU >= 1000000) {
		numGeneratedTripcodesByGPUInMillions += numGeneratedTripcodes_GPU / 1000000;
		numGeneratedTripcodes_GPU           %= 1000000;
	}
	num_generated_tripcodes_spinlock.unlock();
}

double GetNumGeneratedTripcodesByCPU()
{
	num_generated_tripcodes_spinlock.lock();

	double ret =   (double)numGeneratedTripcodesByCPUInMillions * 1000000
	             +         numGeneratedTripcodes_CPU;
	numGeneratedTripcodesByCPUInMillions = 0;
	numGeneratedTripcodes_CPU           = 0;

	num_generated_tripcodes_spinlock.unlock();
	
	return ret;
}

double GetNumGeneratedTripcodesByGPU()
{
	num_generated_tripcodes_spinlock.lock();

	double ret =   (double)numGeneratedTripcodesByGPUInMillions * 1000000
	             +         numGeneratedTripcodes_GPU;
	numGeneratedTripcodesByGPUInMillions = 0;
	numGeneratedTripcodes_GPU           = 0;	

	num_generated_tripcodes_spinlock.unlock();
	
	return ret;
}


double UpdateCurrentStatus(uint64_t startingTime)
{
	current_state_spinlock.lock();
	
	double numGeneratedTripcodes_GPU = GetNumGeneratedTripcodesByGPU();
	double numGeneratedTripcodes_CPU = GetNumGeneratedTripcodesByCPU();
	uint64_t  endingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
	double deltaTime = (endingTime - startingTime             ) * 0.001;

	totalNumGeneratedTripcodes     += numGeneratedTripcodes_GPU + numGeneratedTripcodes_CPU;
	totalNumGeneratedTripcodes_GPU += numGeneratedTripcodes_GPU;
	totalNumGeneratedTripcodes_CPU += numGeneratedTripcodes_CPU;
	totalTime += deltaTime;
	currentSpeed_thisProcess     = ((double)(numGeneratedTripcodes_GPU + numGeneratedTripcodes_CPU) / deltaTime);
	currentSpeed_thisProcess_GPU = ((double) numGeneratedTripcodes_GPU                              / deltaTime);
	currentSpeed_CPU        = ((double)numGeneratedTripcodes_CPU        / deltaTime);
	if (maximumSpeed < currentSpeed_thisProcess)
		maximumSpeed = currentSpeed_thisProcess;
	prevTotalNumGeneratedTripcodes     = totalNumGeneratedTripcodes;
	prevTotalNumGeneratedTripcodes_GPU = totalNumGeneratedTripcodes_GPU;
	prevTotalNumGeneratedTripcodes_CPU = totalNumGeneratedTripcodes_CPU;
	prevNumValidTripcodes     = numValidTripcodes;
	prevNumDiscardedTripcodes = numDiscardedTripcodes;

	current_state_spinlock.unlock();

	return deltaTime;
}

BOOL IsFirstByteSJIS(unsigned char ch)
{
	if (options.maximizeKeySpace) {
		return IS_FIRST_BYTE_SJIS_FULL(ch);
	} else {
		return IS_FIRST_BYTE_SJIS_CONSERVATIVE(ch);
	}
}

void SetCharactersInTripcodeKey(unsigned char *key, int32_t n)
{
	if (options.useOnlyASCIICharactersForKeys) {
		for (int32_t i = 0; i < n; i++){
			key[i] = RandomByte();
			while ((i == 0 && (key[i] == '#' || key[i] == '$')) || !IS_ASCII_KEY_CHAR(key[i]))
				key[i] = (unsigned char)(RandomByte() & 0xff);
		}
	} else if (options.useOneByteCharactersForKeys) {
		for (int32_t i = 0; i < n; i++){
			key[i] = RandomByte();
			while ((i == 0 && (key[i] == '#' || key[i] == '$')) || !IS_ONE_BYTE_KEY_CHAR(key[i]))
				key[i] = (unsigned char)(RandomByte() & 0xff);
		}
	} else {
		BOOL isSecondByteSJIS = FALSE;
		for (int32_t i = 0; i < n; i++){
			if (!isSecondByteSJIS) {
				key[i] = RandomByte();
				while ((i == 0 && (key[i] == '#' || key[i] == '$')) || !(IS_ONE_BYTE_KEY_CHAR(key[i]) || IsFirstByteSJIS(key[i])))
					key[i] = (unsigned char)(RandomByte() & 0xff);
				if (IsFirstByteSJIS(key[i]))
					isSecondByteSJIS = TRUE;
			} else {
				key[i] = (unsigned char)(RandomByte() & 0xff);
				while ((i == 0 && (key[i] == '#' || key[i] == '$')) || !IS_SECOND_BYTE_SJIS(key[i]) || !IS_VALID_SJIS_CHAR(key[i - 1], key[i]))
					key[i] = (unsigned char)(RandomByte() & 0xff);
				isSecondByteSJIS = FALSE;
			}
		}
	}
}

void SetCharactersInTripcodeKeyForSHA1Tripcode(unsigned char *key)
{
	if (options.useOnlyASCIICharactersForKeys) {
		for (int32_t i = 0; i < lenTripcodeKey; i++){
			key[i] = RandomByte();
			while ((i == 0 && (key[i] == '#' || key[i] == '$')) || !IS_ASCII_KEY_CHAR(key[i]))
				key[i] = (unsigned char)(RandomByte() & 0xff);
		}
	} else if (options.useOneByteCharactersForKeys) {
		for (int32_t i = 0; i < lenTripcodeKey; i++){
			key[i] = RandomByte();
			while ((i == 0 && (key[i] == '#' || key[i] == '$')) || !IS_ONE_BYTE_KEY_CHAR(key[i]))
				key[i] = (unsigned char)(RandomByte() & 0xff);
		}
	} else {
		BOOL isSecondByteSJIS = FALSE;
		for (int32_t i = 0; i < lenTripcodeKey; i++){
			if (!isSecondByteSJIS) {
				key[i] = (unsigned char)(RandomByte() & 0xff);
				if (i == 3 || i == lenTripcodeKey - 1) {
					while (!IS_ONE_BYTE_KEY_CHAR(key[i]))
						key[i] = (unsigned char)(RandomByte() & 0xff);
				} else {
					while ((i == 0 && (key[i] == '#' || key[i] == '$')) || !(IS_ONE_BYTE_KEY_CHAR(key[i]) || IsFirstByteSJIS(key[i])))
						key[i] = (unsigned char)(RandomByte() & 0xff);
				}
				isSecondByteSJIS = IsFirstByteSJIS(key[i]);
			} else {
				key[i] = (unsigned char)(RandomByte() & 0xff);
				while (!IS_SECOND_BYTE_SJIS(key[i]) || !IS_VALID_SJIS_CHAR(key[i - 1], key[i]))
					key[i] = (unsigned char)(RandomByte() & 0xff);
				isSecondByteSJIS = FALSE;
			}
		}
	}
}

#ifdef ENABLE_CUDA
void StartCUDADeviceSearchThreads()
{
	int32_t    i;
	uint32_t winThreadID;
	
	ASSERT(numCUDADeviceSearchThreads > 0);

	ERROR0((cuda_device_search_threads = new (std::nothrow) std::thread *[numCUDADeviceSearchThreads]) == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
	ERROR0((CUDADeviceSearchThreadInfoArray = (struct CUDADeviceSearchThreadInfo *)malloc(sizeof(struct CUDADeviceSearchThreadInfo) * numCUDADeviceSearchThreads)) == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
	if (options.GPUIndex == GPU_INDEX_ALL) {
		int32_t CUDADeviceIndex;
		for (CUDADeviceIndex = 0, i = 0; CUDADeviceIndex < CUDADeviceCount; ++CUDADeviceIndex) {
			for (int32_t j = 0; j < CUDA_NUM_THREADS_PER_DEVICE; ++j, ++i) {
				ASSERT(i < numCUDADeviceSearchThreads);
				CUDADeviceSearchThreadInfoArray[i].CUDADeviceIndex = CUDADeviceIndex;
				CUDADeviceSearchThreadInfoArray[i].subindex = j;
				CUDADeviceSearchThreadInfoArray[i].status[0] = '\0';
				CUDADeviceSearchThreadInfoArray[i].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
				CUDA_ERROR(cudaGetDeviceProperties(&CUDADeviceSearchThreadInfoArray[i].properties, CUDADeviceIndex));
			}
		}
	} else if (options.GPUIndex < CUDADeviceCount) {
		ASSERT(numCUDADeviceSearchThreads == CUDA_NUM_THREADS_PER_DEVICE);
		for (i = 0; i < CUDA_NUM_THREADS_PER_DEVICE; ++i) {
			CUDADeviceSearchThreadInfoArray[i].CUDADeviceIndex = options.GPUIndex;
			CUDADeviceSearchThreadInfoArray[i].subindex = i;
			CUDADeviceSearchThreadInfoArray[i].status[0] = '\0';
			CUDADeviceSearchThreadInfoArray[i].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
			CUDA_ERROR(cudaGetDeviceProperties(&CUDADeviceSearchThreadInfoArray[i].properties, options.GPUIndex));
		}
	}

	if (lenTripcode == 12) {
		for (i = 0; i < numCUDADeviceSearchThreads; ++i) {
			cuda_device_search_threads[i] = new (std::nothrow) std::thread(Thread_SearchForSHA1TripcodesOnCUDADevice, &(CUDADeviceSearchThreadInfoArray[i]));
			ERROR0((cuda_device_search_threads[i] == NULL), ERROR_SEARCH_THREAD, "Failed to start a CUDA device search thread.");
		}
	} else {
		ASSERT(lenTripcode == 10);
		for (i = 0; i < numCUDADeviceSearchThreads; ++i) {
			if (CUDADeviceSearchThreadInfoArray[i].properties.major >= 5) {
				cuda_device_search_threads[i] = new (std::nothrow) std::thread(Thread_SearchForDESTripcodesOnCUDADevice_Registers, &(CUDADeviceSearchThreadInfoArray[i]));
			} else {
				cuda_device_search_threads[i] = new (std::nothrow) std::thread(Thread_SearchForDESTripcodesOnCUDADevice, &(CUDADeviceSearchThreadInfoArray[i]));
			}
			ERROR0((cuda_device_search_threads[i] == NULL), ERROR_SEARCH_THREAD, "Failed to start a CUDA device search thread.");
		}
	}
}
#endif

#ifdef ENABLE_OPENCL
void StartOpenCLDeviceSearchThreads()
{
	int32_t i, j;
	char    deviceVendor[LEN_LINE_BUFFER_FOR_SCREEN];
	
	ASSERT(numOpenCLDeviceSearchThreads > 0);

	ERROR0((opencl_device_search_threads = new (std::nothrow) std::thread *[numOpenCLDeviceSearchThreads]) == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
	ERROR0((openCLDeviceSearchThreadInfoArray = new (std::nothrow) struct OpenCLDeviceSearchThreadInfo [numOpenCLDeviceSearchThreads]) == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
	if (options.GPUIndex == GPU_INDEX_ALL) {
		int32_t openCLDeviceIDArrayIndex = 0;
		for (i = 0; i < numOpenCLDeviceSearchThreads; ++i) {
			OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIDArrayIndex], CL_DEVICE_VENDOR, sizeof(deviceVendor), &deviceVendor, NULL));
			openCLDeviceSearchThreadInfoArray[i].openCLDeviceID  = openCLDeviceIDArray[openCLDeviceIDArrayIndex];
			openCLDeviceSearchThreadInfoArray[i].index           = openCLDeviceIDArrayIndex;
			openCLDeviceSearchThreadInfoArray[i].subindex        = -1;
			openCLDeviceSearchThreadInfoArray[i].status[0]       = '\0';
			openCLDeviceSearchThreadInfoArray[i].runChildProcess = openCLRunChildProcesses;
			//
			openCLDeviceSearchThreadInfoArray[i].deviceNo                   = CUDADeviceCount + openCLDeviceIDArrayIndex;
			openCLDeviceSearchThreadInfoArray[i].currentSpeed               = 0;
			openCLDeviceSearchThreadInfoArray[i].averageSpeed               = 0;
			openCLDeviceSearchThreadInfoArray[i].totalNumGeneratedTripcodes = 0;
			openCLDeviceSearchThreadInfoArray[i].numDiscardedTripcodes      = 0;
			openCLDeviceSearchThreadInfoArray[i].numRestarts                = 0;
			openCLDeviceSearchThreadInfoArray[i].timeLastUpdated            = TIME_SINCE_EPOCH_IN_MILLISECONDS;
			openCLDeviceSearchThreadInfoArray[i].subindex                   = 0;
			if (!openCLRunChildProcesses) {
				for (j = 1; j < options.openCLNumThreads; ++j) {
					++i;
					ASSERT(i < numOpenCLDeviceSearchThreads);
					ASSERT(openCLDeviceIDArrayIndex < openCLDeviceCount);
					openCLDeviceSearchThreadInfoArray[i].openCLDeviceID = openCLDeviceIDArray[openCLDeviceIDArrayIndex];
					openCLDeviceSearchThreadInfoArray[i].index          = openCLDeviceIDArrayIndex;
					openCLDeviceSearchThreadInfoArray[i].subindex       = j;
					openCLDeviceSearchThreadInfoArray[i].status[0]      = '\0';
					openCLDeviceSearchThreadInfoArray[i].runChildProcess = FALSE;
					openCLDeviceSearchThreadInfoArray[i].numRestarts = 0;
					openCLDeviceSearchThreadInfoArray[i].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
				}
			} else {
				openCLDeviceSearchThreadInfoArray[i].subindex       = 0;
				for (j = 1; j < options.openCLNumProcesses; ++j) {
					++i;
					ASSERT(i < numOpenCLDeviceSearchThreads);
					ASSERT(openCLDeviceIDArrayIndex < openCLDeviceCount);
					openCLDeviceSearchThreadInfoArray[i].openCLDeviceID = openCLDeviceIDArray[openCLDeviceIDArrayIndex];
					openCLDeviceSearchThreadInfoArray[i].index          = openCLDeviceIDArrayIndex;
					openCLDeviceSearchThreadInfoArray[i].subindex       = j;
					openCLDeviceSearchThreadInfoArray[i].status[0]      = '\0';
					openCLDeviceSearchThreadInfoArray[i].runChildProcess = TRUE;
					//
					openCLDeviceSearchThreadInfoArray[i].deviceNo                   = CUDADeviceCount + openCLDeviceIDArrayIndex;
					openCLDeviceSearchThreadInfoArray[i].currentSpeed               = 0;
					openCLDeviceSearchThreadInfoArray[i].averageSpeed               = 0;
					openCLDeviceSearchThreadInfoArray[i].totalNumGeneratedTripcodes = 0;
					openCLDeviceSearchThreadInfoArray[i].numDiscardedTripcodes      = 0;
					openCLDeviceSearchThreadInfoArray[i].numRestarts = 0;
					openCLDeviceSearchThreadInfoArray[i].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
				}
			}
			++openCLDeviceIDArrayIndex;
		}

	} else if (CUDADeviceCount <= options.GPUIndex && options.GPUIndex < CUDADeviceCount + openCLDeviceCount) {
		int32_t openCLDeviceIDArrayIndex = options.GPUIndex - CUDADeviceCount;
		OPENCL_ERROR(clGetDeviceInfo(openCLDeviceIDArray[openCLDeviceIDArrayIndex], CL_DEVICE_VENDOR, sizeof(deviceVendor), &deviceVendor, NULL));
		openCLDeviceSearchThreadInfoArray[0].openCLDeviceID  = openCLDeviceIDArray[openCLDeviceIDArrayIndex];
		openCLDeviceSearchThreadInfoArray[0].index           = 0;
		openCLDeviceSearchThreadInfoArray[0].subindex        = -1;
		openCLDeviceSearchThreadInfoArray[0].status[0]       = '\0';
		openCLDeviceSearchThreadInfoArray[0].runChildProcess = openCLRunChildProcesses;
		//
		openCLDeviceSearchThreadInfoArray[0].deviceNo                   = CUDADeviceCount + openCLDeviceIDArrayIndex;
		openCLDeviceSearchThreadInfoArray[0].currentSpeed               = 0;
		openCLDeviceSearchThreadInfoArray[0].averageSpeed               = 0;
		openCLDeviceSearchThreadInfoArray[0].totalNumGeneratedTripcodes = 0;
		openCLDeviceSearchThreadInfoArray[0].numDiscardedTripcodes = 0;
		openCLDeviceSearchThreadInfoArray[0].numRestarts = 0;
		openCLDeviceSearchThreadInfoArray[0].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		if (!openCLRunChildProcesses) {
			ASSERT(numOpenCLDeviceSearchThreads == options.openCLNumThreads);
			openCLDeviceSearchThreadInfoArray[0].subindex       = 0;
			for (j = 1; j < options.openCLNumThreads; ++j) {
				openCLDeviceSearchThreadInfoArray[j].openCLDeviceID  = openCLDeviceIDArray[openCLDeviceIDArrayIndex];
				openCLDeviceSearchThreadInfoArray[j].index           = 0;
				openCLDeviceSearchThreadInfoArray[j].subindex        = j;
				openCLDeviceSearchThreadInfoArray[j].status[0]       = '\0';
				openCLDeviceSearchThreadInfoArray[j].runChildProcess = FALSE;
				openCLDeviceSearchThreadInfoArray[j].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
			}
		} else {
			openCLDeviceSearchThreadInfoArray[0].subindex = 0;
			for (j = 1; j < options.openCLNumProcesses; ++j) {
				ASSERT(openCLDeviceIDArrayIndex < openCLDeviceCount);
				openCLDeviceSearchThreadInfoArray[j].openCLDeviceID = openCLDeviceIDArray[openCLDeviceIDArrayIndex];
				openCLDeviceSearchThreadInfoArray[j].index          = 0;
				openCLDeviceSearchThreadInfoArray[j].subindex       = j;
				openCLDeviceSearchThreadInfoArray[j].status[0]      = '\0';
				openCLDeviceSearchThreadInfoArray[j].runChildProcess = TRUE;
				//
				openCLDeviceSearchThreadInfoArray[j].deviceNo                   = CUDADeviceCount + openCLDeviceIDArrayIndex;
				openCLDeviceSearchThreadInfoArray[j].currentSpeed               = 0;
				openCLDeviceSearchThreadInfoArray[j].averageSpeed               = 0;
				openCLDeviceSearchThreadInfoArray[j].totalNumGeneratedTripcodes = 0;
				openCLDeviceSearchThreadInfoArray[j].numDiscardedTripcodes = 0;
				openCLDeviceSearchThreadInfoArray[j].numRestarts = 0;
				openCLDeviceSearchThreadInfoArray[j].timeLastUpdated = TIME_SINCE_EPOCH_IN_MILLISECONDS;
			}	
		}
	}

	if (lenTripcode == 12) {
		for (i = 0; i < numOpenCLDeviceSearchThreads; ++i) {
			opencl_device_search_threads[i] = new std::thread(
				openCLDeviceSearchThreadInfoArray[i].runChildProcess ? Thread_RunChildProcessForOpenCLDevice : Thread_SearchForSHA1TripcodesOnOpenCLDevice,
				&(openCLDeviceSearchThreadInfoArray[i]));
			ERROR0((opencl_device_search_threads[i] == NULL), ERROR_SEARCH_THREAD, "Failed to start a OpenCL device search thread.");
		}
	} else {
		ASSERT(lenTripcode == 10);
		for (i = 0; i < numOpenCLDeviceSearchThreads; ++i) {
			opencl_device_search_threads[i] = new std::thread(
				openCLDeviceSearchThreadInfoArray[i].runChildProcess ? Thread_RunChildProcessForOpenCLDevice : Thread_SearchForDESTripcodesOnOpenCLDevice,
				&(openCLDeviceSearchThreadInfoArray[i]));
			ERROR0((opencl_device_search_threads[i] == NULL), ERROR_SEARCH_THREAD, "Failed to start a OpenCL device search thread.");
		}
	}
}
#endif

void StartGPUSearchThreads()
{
#ifdef ENABLE_CUDA
	if (numCUDADeviceSearchThreads > 0)
		StartCUDADeviceSearchThreads();
#endif
#ifdef ENABLE_OPENCL
	if (numOpenCLDeviceSearchThreads > 0)
		StartOpenCLDeviceSearchThreads();
#endif
}

void StartCPUSearchThreads()
{
	ASSERT(numCPUSearchThreads > 0);

	if (cpu_search_threads)
		delete [] cpu_search_threads;
	ERROR0((cpu_search_threads = new (std::nothrow) std::thread *[numCPUSearchThreads]) == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
	
	for (int32_t i = 0; i < numCPUSearchThreads; ++i) {
		if (lenTripcode == 12) {
			cpu_search_threads[i] = new (std::nothrow) std::thread(Thread_SearchForSHA1TripcodesOnCPU);
		} else {
			ASSERT(lenTripcode == 10);
			cpu_search_threads[i] = new (std::nothrow) std::thread(Thread_SearchForDESTripcodesOnCPU);
		}
		ERROR0((cpu_search_threads[i] == NULL), ERROR_SEARCH_THREAD, "Failed to start a CPU search thread.");
	}
}

#if defined(_WIN32) || defined(__CYGWIN__)
int32_t GetParentProcessID()
{
	DWORD processID = GetCurrentProcessId();
	DWORD parentProcessID = 0xffffffff;
	HANDLE hSnapProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {0};
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	if(Process32First(hSnapProcess, &processEntry)) {
		do {
    		if (processEntry.th32ProcessID == processID) {
    			parentProcessID = processEntry.th32ParentProcessID;
    			break;
			}
		} while( Process32Next(hSnapProcess, &processEntry));
	}

	CloseHandle(hSnapProcess);
	return parentProcessID;
}
#endif

void ListExpandedPatterns()
{
	for (uint32_t i = 0; i < numExpandedPatterns; ++i)
		printf("%u: `%s' @ %d\n", i, expandedPatternArray[i].c, expandedPatternArray[i].pos);
}	

int main(int argc, char **argv)
{
	// Some versions of OpenCL.dll are buggy.
	// /DELAYLOAD:"OpenCL.dll" is also necessary.
#if defined(_WIN64)
	// ERROR0(LoadLibrary(L"OpenCL/x64/OpenCL.dll") == NULL, ERROR_DLL, "Failed to load OpenCL.dll");
	SetDllDirectoryW(L"OpenCL/x64");
#elif defined(_WIN32)
	// ERROR0(LoadLibrary(L"OpenCL/x86/OpenCL.dll") == NULL, ERROR_DLL, "Failed to load OpenCL.dll");
	SetDllDirectoryW(L"OpenCL/x86");
#endif

	BOOL   displayDeviceInformationAndExit = false;
	BOOL   listExpandedPatternsAndExit     = false;

	if (argc > 1) {
		displayDeviceInformationAndExit = (strcmp(argv[1], "--display-device-information") == 0);
		listExpandedPatternsAndExit     = (strcmp(argv[1], "--list-expanded-patterns"    ) == 0);
	}

	InitProcess();
	if (    argc <= 1
		|| (   strcmp(argv[1], "--gpu-list"              ) != 0
		    && !displayDeviceInformationAndExit
			&& !listExpandedPatternsAndExit
		    && strcmp(argv[1], "--output-for-redirection") != 0))
		DisplayCopyrights();
	ObtainOptions(argc, argv);
	if (argc > 1 && strcmp(argv[1], "--gpu-list") == 0)
		ListGPUsAndExit();
	InitSearchDevices((!options.redirection && !listExpandedPatternsAndExit) || displayDeviceInformationAndExit);

	if (displayDeviceInformationAndExit)
		exit(0);

	CreateCharacterTables();
	LoadTargetPatterns(!options.redirection && !listExpandedPatternsAndExit);

	if (listExpandedPatternsAndExit) {
		ListExpandedPatterns();
		exit(0);
	}

	if (!options.redirection)
		OpenTripcodeFile();

#ifdef DEBUG_TEST_NEW_CODE
	if (options.testNewCode)
		TestNewCode();
#endif
	
#ifdef REDIRECTION_ONLY
	if (!options.redirection)
		exit(0);
#endif
	
	if (!options.redirection) {
		printf("TRIPCODES\n");
		printf("=========\n");
	} else {
		printf("[started]\n");
	}
	PrintStatus();
	
	// The main loop.
	uint64_t startingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
	if (searchDevice == SEARCH_DEVICE_GPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU)
		StartGPUSearchThreads();
	if (searchDevice == SEARCH_DEVICE_CPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU)
		StartCPUSearchThreads();
#if defined(_WIN32) || defined(__CYGWIN__)
	HANDLE parentProcess = OpenProcess(SYNCHRONIZE, FALSE, GetParentProcessID());
#endif
	while (!UpdateTerminationState()) {
#if defined(_WIN32) || defined(__CYGWIN__)
		// Break the main loop if necessary.
		if (options.redirection && WaitForSingleObject(parentProcess, 0) != WAIT_TIMEOUT)
			break;
#endif

		// Wait for the duration of STATUS_UPDATE_INTERVAL.
		for (int32_t i = 0; i < NUM_CHECKS_PER_INTERVAL; ++i) {
			// Break the loop if the search is paused.
			if (UpdatePauseState())
				break;

			// Break the loop if the search was terminated.
			if (UpdateTerminationState())
				break;

#if defined(_WIN32) || defined(__CYGWIN__)
			// Break the loop if the parent process has already quit.
			if (options.redirection && WaitForSingleObject(parentProcess, 0) != WAIT_TIMEOUT)
				break;
#endif

			sleep_for_milliseconds((uint32_t)(STATUS_UPDATE_INTERVAL * 1000 / NUM_CHECKS_PER_INTERVAL));
		}
		if (UpdateTerminationState())
			break;
		UpdateCurrentStatus(startingTime);
		
		// Pause searching if necessary.
		while (UpdatePauseState()) {
			// Break the loop if the search was terminated.
			if (UpdateTerminationState())
				break;

			// Break the loop if the parent process has already quit.
#if defined(_WIN32) || defined(__CYGWIN__)
			if (options.redirection && WaitForSingleObject(parentProcess, 0) != WAIT_TIMEOUT)
				break;
#endif

			KeepSearchThreadsAlive();
			sleep_for_milliseconds(PAUSE_INTERVAL);
		}
		if (UpdateTerminationState())
			break;
				
		//
		CheckSearchThreads();
		startingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		PrintStatus();
		
		// Warn the user if the speed drops suddenly.
		if (!options.redirection && options.warnSpeedDrop && currentSpeed_thisProcess < maximumSpeed * SPEED_DROP_WARNING_THRESHOLD)
			printf("\a");
	}

#if defined(_WIN32) || defined(__CYGWIN__)
	// Close handles.
	CloseHandle(parentProcess);
#endif

	// Terminate search threads.
	SetTerminationState();
	BOOL allThreadsHaveExited;
	startingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
	uint64_t currentTime, deltaTime;
	do {
		sleep_for_milliseconds(100);
		allThreadsHaveExited = TRUE;
#if defined(_WIN32) || defined(__CYGWIN__)
		for (int32_t i = 0; i < numCUDADeviceSearchThreads; ++i) {
			if (WaitForSingleObject(cuda_device_search_threads[i]->native_handle(), 0) != WAIT_OBJECT_0) {
				allThreadsHaveExited = FALSE;
				break;
			}
		}
		for (int32_t i = 0; i < numOpenCLDeviceSearchThreads; ++i) {
			if (WaitForSingleObject(opencl_device_search_threads[i]->native_handle(), 0) != WAIT_OBJECT_0) {
				allThreadsHaveExited = FALSE;
				break;
			}
		}
		for (int32_t i = 0; i < numCPUSearchThreads; ++i) {
			if (WaitForSingleObject(cpu_search_threads[i]->native_handle(), 0) != WAIT_OBJECT_0) {
				allThreadsHaveExited = FALSE;
				break;
			}
		}
#endif
		currentTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		deltaTime = currentTime - startingTime;
	} while (deltaTime < 10 * 1000 && !allThreadsHaveExited);	

	ReleaseResources();

	reset_cursor_pos(prevLineCount + 1);

	return 0;
}
