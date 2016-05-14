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



///////////////////////////////////////////////////////////////////////////////
// NATIVE CODES                                                              //
///////////////////////////////////////////////////////////////////////////////

#ifdef DEBUG_TEST_NEW_CODE

extern "C" void TestASM();

void TestNewCode()
{
#ifdef USE_YASM
	unsigned char *p = (unsigned char *)TestASM;
        int32_t i;
        void (*code)();
        int32_t functionSize;

        for (; strcmp((char *)p, "THIS_IS_THE_END_OF_THE_FUNCTION") != 0; ++p)
                ;
        functionSize = p - (unsigned char *)TestASM;
        code = (void (*)())VirtualAllocEx(GetCurrentProcess(), 0, functionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		memcpy((void *)code, (void *)TestASM, functionSize);
        printf("functionSize = %d\n", functionSize);

        (*code)();

        printf("\n");
                        
        for (i = 0, p = (unsigned char *)TestASM; i < functionSize; ++i, ++p) {
                if (i % 16 == 0)
                        printf("%02x", i);
                printf(" %02x", *p);
                if (i % 16 == 16 - 1)
                        printf("\n");
        }
#endif

		printf("\nHit return key to exit.\n");
        getchar();
        exit(0);
}

#endif // DEBUG_TEST_NEW_CODE
