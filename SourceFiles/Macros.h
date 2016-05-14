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
// MACROS                                                                    //
///////////////////////////////////////////////////////////////////////////////

#ifndef _MSC_VER
#define _getch()
#endif

#define ERROR0(cond, code, msg)                                   \
	if ((cond) && !GetErrorState()) {                                                   \
		SetErrorState(); \
		if (options.redirection) {                                \
			fprintf(stderr, "%d\n", (code));                      \
			fflush(stderr);                                       \
			printf("[error],%d\n", (code));                      \
			fflush(stdout);                                       \
		} else {                                                  \
			reset_cursor_pos(prevLineCount);                        \
			printf("\nERROR\n=====\n  %s\n\a\n  Hit any key to exit.", (msg));                \
			_getch();                                            \
			show_cursor();                                         \
		}                                                         \
		exit(1);                                           \
	}                                                             \
	
#define ERROR1(cond, code, msg, arg1)                     \
	if ((cond) && !GetErrorState()) {                                           \
		SetErrorState(); \
		if (options.redirection) {                        \
			char _msg[256];                               \
			sprintf(_msg, msg, (arg1));   \
			fprintf(stderr, "%d,%s\n", (code), _msg);   \
			fflush(stderr);                               \
			printf("[error],%d\n", (code));                      \
			fflush(stdout);                                       \
		} else {                                          \
			char line[256];                               \
			reset_cursor_pos(prevLineCount);                        \
			strcpy(line, "\nERROR\n=====\n  ");           \
			strcat(line, (msg));                          \
			strcat(line, "\n\a\n  Hit any key to exit.");                          \
			printf(line, (arg1));                         \
			_getch();                                    \
			show_cursor();                                 \
		}                                                 \
		exit(1);                                   \
	}                                                     \

#define CUDA_ERROR(error)                                                                     \
	{                                                                                         \
		cudaError_t _errorCode;                                                               \
		if ((_errorCode = (error)) != cudaSuccess && !GetErrorState()) {                                          \
			SetErrorState(); \
			if (options.redirection) {                                                        \
				fprintf(stderr, "%d\n", ERROR_CUDA);                                          \
				fflush(stderr);                                                               \
				printf("[error],%d\n", ERROR_CUDA);                                           \
				fflush(stdout);                                                               \
			} else {                                                                          \
				reset_cursor_pos(prevLineCount);                                                \
				const char *p = __FILE__;                                           \
				const char *file_name = p;                                           \
				for (; *p; ++p)                                                               \
				    if (*p == '\\' || *p == '/')                                              \
						file_name = p + 1;                                                    \
				printf("\nERROR\n=====\n  CUDA Function Call Failed: %s [%d] (file '%s', line %d)\n  The video card may be low on resources.\n\a\n  Hit any key to exit.", \
						cudaGetErrorString(_errorCode), (int32_t)_errorCode, file_name, __LINE__); \
				_getch();                                                                     \
				show_cursor();                                                                 \
			}                                                                                 \
			exit(1);                                                                   \
		}                                                                                     \
	}                                                                                         \

#define OPENCL_ERROR(error)                                                                        \
	{                                                                                              \
		cl_int _errorCode;                                                                         \
		if ((_errorCode = (error)) != CL_SUCCESS && !GetErrorState()) {                                                \
			SetErrorState();                                                                           \
			if (options.redirection) {                                                             \
				fprintf(stderr, "%d\n", ERROR_OPENCL);                                             \
				fflush(stderr);                                                                    \
				printf("[error],%d\n", ERROR_OPENCL);                                              \
				fflush(stdout);                                                                    \
			} else {                                                                               \
				reset_cursor_pos(prevLineCount);                                                     \
				const char *p = __FILE__;                                           \
				const char *file_name = p;                                           \
				for (; *p; ++p)                                                               \
				    if (*p == '\\' || *p == '/')                                              \
						file_name = p + 1;                                                    \
				printf("\nERROR\n=====\n  OpenCL Function Call Failed: %s (file '%s', line %d)\n\a\n  Hit any key to exit.", \
						ConvertOpenCLErrorCodeToString(_errorCode), file_name, __LINE__);          \
				_getch();                                                                          \
				show_cursor();                                                                      \
			}                                                                                      \
			exit(1);                                                                        \
		}                                                                                          \
	}                                                                                              \

#define ASSERT(cond)                                                                                    \
	if (!(cond) && !GetErrorState()) {                                                                                      \
		SetErrorState(); \
		if (options.redirection) {                                                                      \
			fprintf(stderr, "%d\n", ERROR_ASSERTION);                                                   \
			fflush(stderr);                                                                             \
			printf("[error],%d\n", ERROR_ASSERTION);                                              \
			fflush(stdout);                                                                    \
		} else {                                                                                        \
			reset_cursor_pos(prevLineCount);                        \
			printf("\nERROR\n=====\n  Assertion Failed: file %s, line %d\n\a\n  Hit any key to exit.", __FILE__, __LINE__); \
			_getch();                                                                                  \
			show_cursor();                                                                               \
		}                                                                                               \
		exit(1);                                                                                 \
	}                                                                                                   \

// for 1-byte characters
#define BASE64_CHAR_TO_INDEX(c)                       \
	(('A' <= (c) && (c) <= 'Z') ? ((c) - 'A'     ) :  \
	 ('a' <= (c) && (c) <= 'z') ? ((c) - 'a' + 26) :  \
	 ('0' <= (c) && (c) <= '9') ? ((c) - '0' + 52) :  \
	 (              (c) == '.') ? 62               :  \
	                              63                ) \

// for ExpandedPattern
// Note: SPECIAL_CHAR_DIGIT < '[0-9]' < SPECIAL_CHAR_UPPPER < '[A-Z]' < SPECIAL_CHAR_LOWER < '[a-z]'
#define SPECIAL_CHAR_DIGIT '%'
#define SPECIAL_CHAR_UPPER '='
#define SPECIAL_CHAR_LOWER '^'
#define SPECIAL_CHAR_ALL   '@'
#define IS_SPECIAL_CHARACTER(c) ((c) == SPECIAL_CHAR_DIGIT || (c) == SPECIAL_CHAR_UPPER || (c) == SPECIAL_CHAR_LOWER || (c) == SPECIAL_CHAR_ALL)

// for Shift-JIS characters
#define IS_BASE64_CHAR(c)             \
	(   (0x2e <= (c) && (c) <= 0x39)  \
	 || (0x41 <= (c) && (c) <= 0x5a)  \
	 || (0x61 <= (c) && (c) <= 0x7a)) \

#define IS_LAST_CHAR_OF_TRIPCODE(c)                        \
    (   IS_BASE64_CHAR(c)                                  \
     && (   (lenTripcode == 12)                            \
         || (((charToIndexTableForDES[c]) & 0x03) == 0x00))) \

// ',', '%', and '+' are excluded in the following macro.
// '<', '>', '"' (0x22), '&' (0x26) and '#' (0x23) cannot be used as part of keys at 4chan.org.
#define IS_ASCII_KEY_CHAR(c)          \
	(   (0x21 == (c)               )  \
	 || (0x24 == (c)               )  \
	 || (0x27 <= (c) && (c) <= 0x2a)  \
	 || (0x2d <= (c) && (c) <= 0x3b)  \
	 || (0x3d <= (c) && (c) <= 0x3d)  \
	 || (0x3f <= (c) && (c) <= 0x7e)) \

// ',', '%', and '+' are excluded in the following macro.
#define IS_ONE_BYTE_KEY_CHAR(c)       \
	(   (0x21 <= (c) && (c) <= 0x24)  \
	 || (0x26 <= (c) && (c) <= 0x2a)  \
	 || (0x2d <= (c) && (c) <= 0x7e)  \
	 || (0xa1 <= (c) && (c) <= 0xdf)) \

// Shift-JIS characters that have no UNICODE counterparts are intentionally excluded.
/*
#define IS_FIRST_BYTE_SJIS(c)         \
	(   (0x81 <= (c) && (c) <= 0x9f)  \
	 || (0xe0 <= (c) && (c) <= 0xef)) \

*/
#define IS_FIRST_BYTE_SJIS_FULL(c)    \
	(   (0x81 <= (c) && (c) <= 0x84)  \
	 || (0x88 <= (c) && (c) <= 0x9f)  \
	 || (0xe0 <= (c) && (c) <= 0xea)) \

#define IS_FIRST_BYTE_SJIS_CONSERVATIVE(c) \
	(   (0x89 <= (c) && (c) <= 0x97)  \
	 || (0x99 <= (c) && (c) <= 0x9f)  \
	 || (0xe0 <= (c) && (c) <= 0xe9)) \

#define IS_FIRST_BYTE_SJIS(c) IS_FIRST_BYTE_SJIS_FULL(c)

// In this macro, 0x80 is excluded becauce 10-character tripcodes with 0x80
// as the second byte of a Shift-JIS character in the key is not compatible with 2ch.net
// because there is a bug in the way 2ch.net handles tripcodes. See:
// http://sourceforge.jp/projects/naniya/wiki/2chtrip 
#define IS_SECOND_BYTE_SJIS(c)        \
	(   (0x40 <= (c) && (c) <= 0x7e)  \
	 || (0x81 <= (c) && (c) <= 0xfc))

// 0x81f0 is excluded here because it does not work well with Google Chrome.
// See: http://anago.2ch.net/test/read.cgi/software/1362648003/942-946n
#define IS_VALID_SJIS_CHAR(b1, b2)                            \
	(   IS_FIRST_BYTE_SJIS_FULL(b1)                           \
	 && IS_SECOND_BYTE_SJIS(b2)                               \
	 && !(                                                    \
             ((b1) == 0x81 && 0xad <= (b2) && (b2) <= 0xb7)   \
          || ((b1) == 0x81 && 0xc0 <= (b2) && (b2) <= 0xc7)   \
          || ((b1) == 0x81 && 0xcf <= (b2) && (b2) <= 0xd9)   \
          || ((b1) == 0x81 && 0xe9 <= (b2) && (b2) <= 0xef)   \
          || ((b1) == 0x81 && 0xf8 <= (b2) && (b2) <= 0xfb)   \
	                                                          \
	      || ((b1) == 0x82 && 0x40 <= (b2) && (b2) <= 0x4e)   \
          || ((b1) == 0x82 && 0x59 <= (b2) && (b2) <= 0x5f)   \
          || ((b1) == 0x82 && 0x7a <= (b2) && (b2) <= 0x80)   \
          || ((b1) == 0x82 && 0x9b <= (b2) && (b2) <= 0x9e)   \
          || ((b1) == 0x82 && 0xf2 <= (b2) && (b2) <= 0xfc)   \
	                                                          \
          || ((b1) == 0x83 && 0x97 <= (b2) && (b2) <= 0x9e)   \
          || ((b1) == 0x83 && 0xb7 <= (b2) && (b2) <= 0xbe)   \
          || ((b1) == 0x83 && 0xd7 <= (b2) && (b2) <= 0xfc)   \
	                                                          \
          || ((b1) == 0x84 && 0x61 <= (b2) && (b2) <= 0x6f)   \
          || ((b1) == 0x84 && 0x92 <= (b2) && (b2) <= 0x9e)   \
          || ((b1) == 0x84 && 0xbf <= (b2) && (b2) <= 0xfc)   \
	                                                          \
          || ((b1) == 0x88 && 0x40 <= (b2) && (b2) <= 0x9e)   \
	                                                          \
          || ((b1) == 0x98 && 0x73 <= (b2) && (b2) <= 0x9e)   \
	                                                          \
          || ((b1) == 0xea && 0xa5 <= (b2) && (b2) <= 0xfc)   \
		                                                      \
          || ((b1) == 0x81 && (b2) == 0xf0                ))) \

#ifdef USE_TABLE_FOR_SEED

extern unsigned char charTableForSeed[256];
#define CONVERT_CHAR_FOR_SALT(ch) (charTableForSeed[(unsigned char)(ch)])

#else

// This macro does not work for 2ch.

#define CONVERT_CHAR_FOR_SALT(ch)                            \
	((IS_BASE64_CHAR(ch)          ) ? ((ch)             ) :  \
	 (0x3a <= (ch) && (ch) <= 0x40) ? ((ch) - 0x3a + 'A') :  \
	 (0x5b <= (ch) && (ch) <= 0x60) ? ((ch) - 0x5b + 'a') :  \
                                      ( '.'             )  ) 
#endif

#define RELEASE_AND_SET_TO_NULL(p, releaseFunc) \
	if (p) {                                    \
		releaseFunc(p);                         \
		(p) = NULL;                             \
	}                                           
