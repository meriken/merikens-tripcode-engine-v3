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



struct Tripcode {
	// uint32_t length;
	unsigned char c[MAX_LEN_TRIPCODE];
};

struct TripcodeKey {
	// uint32_t length;
	unsigned char c[MAX_LEN_TRIPCODE_KEY];
};

struct TripcodeKeyPair {
	Tripcode    tripcode;
	TripcodeKey key;
};

struct ExpandedPattern {
	int32_t pos;
	unsigned char c[MAX_LEN_EXPANDED_PATTERN + 1];
};

struct RegexPattern {
	unsigned char   original [MAX_LEN_TARGET_PATTERN + 1];
	unsigned char   expanded [MAX_LEN_TARGET_PATTERN + 1];
	unsigned char   remaining[MAX_LEN_TARGET_PATTERN + 1];
	BOOL            startsAtFirstChar;
	BOOL            endsAtLastChar;
	BOOL            wereVerticalBarsProcessed;
	//
	int32_t         depth;
	unsigned char   expandedAtLowerDepth [MAX_NUM_DEPTHS_IN_REGEX_PATTERN - 1][MAX_LEN_TARGET_PATTERN + 1];
	unsigned char   remainingAtLowerDepth[MAX_NUM_DEPTHS_IN_REGEX_PATTERN - 1][MAX_LEN_TARGET_PATTERN + 1];
	//
	int32_t         numSubexpressions;
	unsigned char   subexpressions[MAX_NUM_SUBEXPRESSIONS_IN_REGEX_PATTERN][MAX_LEN_TARGET_PATTERN + 1];
	BOOL            wereSubexpressionsSet[MAX_NUM_SUBEXPRESSIONS_IN_REGEX_PATTERN];
	int32_t         subexpressionIndexAtLowerDepth[MAX_NUM_DEPTHS_IN_REGEX_PATTERN - 1];
	BOOL            expandSpecialCharactersInParentheses;
};

struct GPUOutput {
	uint32_t        numGeneratedTripcodes;
	unsigned char   numMatchingTripcodes;
	TripcodeKeyPair pair;
};

struct Options {
	int32_t GPUIndex;
	int32_t CUDANumBlocksPerSM;
	BOOL beepWhenNewTripcodeIsFound;
	BOOL outputInvalidTripcode;
	BOOL warnSpeedDrop;
	int32_t  searchDevice;
	BOOL testNewCode;
	int32_t  numCPUSearchThreads;
	BOOL redirection;
	int32_t openCLNumWorkItemsPerCU;
	int32_t openCLNumWorkItemsPerWG;
	int32_t openCLNumThreads;
	BOOL useOneByteCharactersForKeys;
	BOOL searchForHisekiOnCPU;
	BOOL searchForKakuhiOnCPU;
	BOOL searchForKaibunOnCPU;
	BOOL searchForYamabikoOnCPU;
	BOOL searchForSourenOnCPU;
	BOOL searchForKagamiOnCPU;
	BOOL useOpenCLForCUDADevices;
	BOOL isAVXEnabled;
	BOOL useOnlyASCIICharactersForKeys;
	BOOL maximizeKeySpace;
	BOOL isAVX2Enabled;
	BOOL openCLRunChildProcesses;
	int32_t  openCLNumProcesses;
	BOOL checkTripcodes;
	BOOL enableGCNAssembler;
};

#ifdef ENABLE_CUDA

struct CUDADeviceSearchThreadInfo {
	int32_t        CUDADeviceIndex;
	int32_t        subindex;
	cudaDeviceProp properties;
	char           status[LEN_LINE_BUFFER_FOR_SCREEN];
	std::mutex     mutex;
	uint64_t       timeLastUpdated;
};

#endif

#ifdef ENABLE_OPENCL

struct OpenCLDeviceSearchThreadInfo {
	cl_device_id openCLDeviceID;
	int32_t      index;
	int32_t      subindex;
	char         status[LEN_LINE_BUFFER_FOR_SCREEN];
	int32_t      deviceNo;
	double       currentSpeed;
	double       averageSpeed;
	double       totalNumGeneratedTripcodes;
	uint32_t     numDiscardedTripcodes;
	uint32_t     numRestarts;
	BOOL         runChildProcess;
	uint64_t     timeLastUpdated;
};

#endif

#ifndef __CUDACC__

class spinlock {
	std::atomic_flag flag;

public:
	spinlock();
	void lock();
	void unlock();
};

namespace mte {
	class named_event {
		std::string data_name;
#if defined(_WIN32) || defined(__CYGWIN__)
		/* HANDLE */ void *native_event_handle;
#endif

	public:
		named_event();
		~named_event();
		bool is_open();
		bool open_or_create(const char *arg_name);
		void wait();
		bool poll();
		std::string name();
	};
}

#endif



