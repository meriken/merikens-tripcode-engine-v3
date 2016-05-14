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
#include <boost/multiprecision/cpp_dec_float.hpp>



///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES, CONSTANTS, AND MACROS FOR WIN32 AND CUDA                //
///////////////////////////////////////////////////////////////////////////////

// Target patterns
ExpandedPattern     *expandedPatternArray     = NULL;
uint32_t         numExpandedPatterns       = 0;
uint32_t         sizeExpandedPatternArray = 0;
uint32_t        *tripcodeChunkArray       = NULL;        
uint32_t         numTripcodeChunk         = 0;
uint32_t         sizeTripcodeChunkArray   = 0;
struct RegexPattern *regexPatternArray        = NULL;
uint32_t                  sizeRegexPatternArray    = 0;
uint32_t                  numRegexPattern          = 0;
unsigned char        chunkBitmap[CHUNK_BITMAP_SIZE];
unsigned char        mediumChunkBitmap[MEDIUM_CHUNK_BITMAP_SIZE];
unsigned char        smallChunkBitmap[SMALL_CHUNK_BITMAP_SIZE];
unsigned char        compactMediumChunkBitmap[COMPACT_MEDIUM_CHUNK_BITMAP_SIZE];
unsigned char        compactSmallChunkBitmap[COMPACT_SMALL_CHUNK_BITMAP_SIZE];
int32_t                  minLenExpandedPattern;
int32_t                  maxLenExpandedPattern;
BOOL                 searchForSpecialPatternsOnCPU = FALSE;



///////////////////////////////////////////////////////////////////////////////
// FUNCTIONS                                                                 //
///////////////////////////////////////////////////////////////////////////////

int32_t CompareUINT32(const void *ptrLeft, const void *ptrRight)
{
	uint32_t left  = *(uint32_t *)ptrLeft;
	uint32_t right = *(uint32_t *)ptrRight;

	return (left < right) ? -1 :
	       (left > right) ?  1 :
                             0;
}

int32_t CompareString(const void *ptrLeft, const void *ptrRight)
{
	return strcmp((char *)ptrLeft, (char *)ptrRight);
}

int32_t CompareSpecialCharacter(const void *ptrLeft, const void *ptrRight)
{
	unsigned char left  = *(unsigned char *)ptrLeft;
	unsigned char right = *(unsigned char *)ptrRight;

	if (   (left  == SPECIAL_CHAR_DIGIT && '0' <= right && right <= '9')
	    || (left  == SPECIAL_CHAR_UPPER && 'A' <= right && right <= 'Z')
	    || (left  == SPECIAL_CHAR_LOWER && 'a' <= right && right <= 'z')
	    || (right == SPECIAL_CHAR_DIGIT && '0' <= left  && left  <= '9')
	    || (right == SPECIAL_CHAR_UPPER && 'A' <= left  && left  <= 'Z')
	    || (right == SPECIAL_CHAR_LOWER && 'a' <= left  && left  <= 'z')
	    ||  left  == SPECIAL_CHAR_ALL
	    ||  right == SPECIAL_CHAR_ALL                                   ) {
		return 0;
	} else {
		return (int32_t)left - (int32_t)right;
	}
}

int32_t CompareExpandedPattern(const void *ptrLeft, const void *ptrRight)
{
	ExpandedPattern *left  = (ExpandedPattern *)ptrLeft;
	ExpandedPattern *right = (ExpandedPattern *)ptrRight;
	int32_t ret;

	if (left->pos != right->pos) {
		ret = (int32_t)(left->pos) - (int32_t)(right->pos);	
	} else {
		int32_t i;
		for (i = 0; left->c[i] != '\0' && right->c[i] != '\0' && CompareSpecialCharacter(&(left->c[i]), &(right->c[i])) == 0; ++i)
			;
		ret = CompareSpecialCharacter(&(left->c[i]), &(right->c[i]));
	}
	return ret;
}

int32_t CompareExpandedPatternExactly(const void *ptrLeft, const void *ptrRight)
{
	ExpandedPattern *left  = (ExpandedPattern *)ptrLeft;
	ExpandedPattern *right = (ExpandedPattern *)ptrRight;
	
	if (left->pos != right->pos) {
		return (int32_t)(left->pos) - (int32_t)(right->pos);	
	} else {
		return strcmp((char *)(left->c), (char *)(right->c));
	}
}

int32_t CompareStringWithSpecicalChar(unsigned char *left, unsigned char *right, int32_t len)
{
	int32_t i;
	for (i = 0; i < len && left[i] != '\0' && right[i] != '\0' && CompareSpecialCharacter(&(left[i]), &(right[i])) == 0; ++i)
		;
	if (i >= len) {
		return 0;
	} else {
		return CompareSpecialCharacter(&(left[i]), &(right[i]));
	}
}

size_t uniq(void *array, size_t num, size_t size, int32_t (*comp)(const void *, const void *))
{
	char *start = (char *)array;
	char *stop = (char *)array + (size * (num - 1));

	char *dst = start;
	char *p = start;

	while (p <= stop){
		char *q = p;
		while ((q < stop) && comp(q, q + size)){
			q += size;
		}

		size_t elements = ((q - p) / size) + 1;
		memmove(dst, p, size * elements);
		dst += size * elements;

		p = q + size;
		while ((p <= stop) && comp(q, p) == 0){
			p += size;
		}
	}

	return (dst - start) / size;
}

#define EXPAND_ARRAY_IF_NECESSARY(type, array, size, num)                \
{                                                                        \
	if ((array) == NULL) {                                               \
		(array) = (type *)malloc(sizeof(type) * MIN_SIZE_ARRAY);         \
		ERROR0((array) == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));  \
		(num)       = 0;                                                 \
		(size) = MIN_SIZE_ARRAY;                                         \
	} else if ((size) <= (num)) {                                        \
		type *oldArray = (array);                                        \
		uint32_t newSize = (size) * 2;                               \
		type *newArray = (type *)malloc(sizeof(type) * (size_t)newSize); \
		ERROR0(newArray == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY)); \
		for (uint32_t i = 0; i < (size); ++i)                        \
			newArray[i] = oldArray[i];                                   \
		free(oldArray);                                                  \
		(array) = newArray;                                              \
		(size) = newSize;                                                \
	}                                                                    \
}

void AddNewTripcodeChunk(uint32_t newTripcodeChunk)
{
	EXPAND_ARRAY_IF_NECESSARY(uint32_t, tripcodeChunkArray, sizeTripcodeChunkArray, numTripcodeChunk);
	ASSERT(numTripcodeChunk < sizeTripcodeChunkArray);
	tripcodeChunkArray[numTripcodeChunk++] = newTripcodeChunk;
}

BOOL CreateTripcodeChunk(unsigned char *tripcode, uint32_t *tripcodeChunk, BOOL lastFiveCharacters)
{
	unsigned char indexArray[5];
	int32_t   pos = (lastFiveCharacters) ? (strlen((char *)tripcode) - 5) : 0;

	for (int32_t i = 0; i < 5; i++) {
		// printf("tripcode[%d] = '%c'\n", i, tripcode[i]);
		// printf("IS_BASE64_CHAR(tripcode[i]): %d\n", IS_BASE64_CHAR(tripcode[i]));
		if (!IS_BASE64_CHAR(tripcode[pos + i]))
			return FALSE;
		if (lenTripcode == 12) {
			indexArray[i] = BASE64_CHAR_TO_INDEX(tripcode[pos + i]);
		} else {
			ASSERT(lenTripcode == 10);
			indexArray[i] = charToIndexTableForDES[tripcode[pos + i]];
			// printf("CreateTripcodeChunk(): indexArray[%d] = %d\n", i, indexArray[i]);
		}
	}
	// TO DO: THE FOLLOWING LINE SHOULD BE SIMPLIFIED.
	*tripcodeChunk =   (((indexArray[0]<<2 | indexArray[1]>>4) & 0xff) << 22)
                     | (((indexArray[1]<<4 | indexArray[2]>>2) & 0xff) << 14)
	                 | (((indexArray[2]<<6 | indexArray[3]   ) & 0xff) <<  6)
	                 | (  indexArray[4]                        & 0x3f       );
	return TRUE;
}

void AddNewExpandedPattern(unsigned char *s, int32_t pos)
{
#ifdef DEBUG_REGEX
	printf("AddNewExpandedPattern(): s = `%s', pos = %d\n", s, pos);
#endif
	ASSERT(pos                     <  lenTripcode);
	ASSERT(pos + strlen((char *)s) <= (size_t)lenTripcode);
	EXPAND_ARRAY_IF_NECESSARY(ExpandedPattern, expandedPatternArray, sizeExpandedPatternArray, numExpandedPatterns);
	strncpy((char *)&(expandedPatternArray[numExpandedPatterns].c[0]),
	        (char *)s,
	        lenTripcode);
	expandedPatternArray[numExpandedPatterns].c[lenTripcode] = '\0';
	expandedPatternArray[numExpandedPatterns].pos = pos;
	++numExpandedPatterns;
}

int32_t CompareRegexPattern(const void *ptrLeft, const void *ptrRight)
{
	RegexPattern *left  = (RegexPattern *)ptrLeft;
	RegexPattern *right = (RegexPattern *)ptrRight;
	int32_t leftOpCount = 0, rightOpCount = 0;
	
	for (int32_t i = strlen((char *)(left->remaining)) - 1; i >= 0; --i) {
		if (left->remaining[i] == '*' || left->remaining[i] == '+')
			++leftOpCount;
	}
	for (int32_t i = strlen((char *)(right->remaining)) - 1; i >= 0; --i) {
		if (right->remaining[i] == '*' || right->remaining[i] == '+')
			++rightOpCount;
	}
	if (leftOpCount != rightOpCount) {
		return -((int32_t)(leftOpCount) - (int32_t)(rightOpCount)); // Patterns with more operators come first.
	} else {
		return (int32_t)strlen((char *)(left->expanded)) - (int32_t)strlen((char *)(right->expanded));
	}
}

void PushRegexPattern(RegexPattern *pattern)
{
#ifdef DEBUG_REGEX
	printf("PushRegexPattern(): expanded = `%s', remaining = `%s'\n", pattern->expanded, pattern->remaining);
#endif
	EXPAND_ARRAY_IF_NECESSARY(RegexPattern, regexPatternArray, sizeRegexPatternArray, numRegexPattern);
	regexPatternArray[numRegexPattern++] = *pattern;
	// printf("regexPatternArray[numRegexPattern - 1].remainingAtLowerDepth[0] = `%s'\n", regexPatternArray[numRegexPattern - 1].remainingAtLowerDepth[0]);
}

void PopRegexPattern(RegexPattern *pattern)
{
	ASSERT(numRegexPattern > 0);
	*pattern = regexPatternArray[--numRegexPattern];
}

#define DISCARD_FIRST_N_CHARACTERS(s, n) \
{                                        \
	int32_t i, len = strlen((char *)(s));    \
	for (i = 0; i < len - (n); ++i)      \
		(s)[i] = (s)[i + (n)];           \
	(s)[i] = '\0';                       \
}

void ProcessNextRegexPattern()
{
	RegexPattern pattern;

	if (numRegexPattern <= 0)
		return;
	
	PopRegexPattern(&pattern);
	
#ifdef DEBUG_REGEX
	printf("ProcessNextRegexPattern(): expanded = `%s', remaining = `%s', depth = %d\n", pattern.expanded, pattern.remaining, pattern.depth);
	// printf("pattern.remainingAtLowerDepth[0] = `%s'\n", pattern.remainingAtLowerDepth[0]);
#endif
	
	if (pattern.remaining[0] == '\0') {
		int32_t len = strlen((char *)pattern.expanded);
		if (MIN_LEN_EXPANDED_PATTERN <= len && len <= lenTripcode && pattern.depth == 0) {
			// The process of expansion is now complete.
			// Save the expanded pattern.
			if (pattern.startsAtFirstChar && (len == lenTripcode || !pattern.endsAtLastChar)) {
				AddNewExpandedPattern(pattern.expanded, 0);
			} else if (pattern.endsAtLastChar && (len == lenTripcode || !pattern.startsAtFirstChar)) {
				AddNewExpandedPattern(pattern.expanded, lenTripcode - len);
			} else if (   !pattern.startsAtFirstChar
				       && !pattern.endsAtLastChar
			           && len <= lenTripcode) {
				for (int32_t posExpandedPattern = 0; posExpandedPattern <= lenTripcode - len; ++posExpandedPattern)
					AddNewExpandedPattern(pattern.expanded, posExpandedPattern);
			}
		} else if (len <= lenTripcode && pattern.depth > 0) {
			// Save a new subexpression and pop out the previous state from the stack.
			unsigned char tmp[MAX_LEN_TARGET_PATTERN + 1];
			--(pattern.depth);
			// printf("Possible subexpression: `%s'\n", pattern.expanded);
			int32_t subexpressionIndex = pattern.subexpressionIndexAtLowerDepth[pattern.depth];
			if (0 <= subexpressionIndex && subexpressionIndex < MAX_NUM_SUBEXPRESSIONS_IN_REGEX_PATTERN) {
				strcpy((char *)pattern.subexpressions[subexpressionIndex], (char *)pattern.expanded);
				pattern.wereSubexpressionsSet[subexpressionIndex] = TRUE;
			}
			// printf("pattern.remainingAtLowerDepth[0] = `%s'\n", pattern.remainingAtLowerDepth[0]);
			strcpy((char *)tmp, (char *)pattern.expandedAtLowerDepth[pattern.depth]);
			strcat((char *)tmp, (char *)pattern.expanded);
			strcpy((char *)pattern.expanded, (char *)tmp);
			pattern.expandedAtLowerDepth[pattern.depth][0] = '\0';
			strcpy((char *)pattern.remaining, (char *)pattern.remainingAtLowerDepth[pattern.depth]);
			pattern.remainingAtLowerDepth[pattern.depth][0] = '\0';	
	 		// printf("pattern.expandedAtLowerDepth[pattern.depth]: `%s'\n", pattern.expandedAtLowerDepth[pattern.depth]);
			// printf("pattern.remaining: `%s'\n", pattern.remaining);
			PushRegexPattern(&pattern);
		}

	} else if (strlen((char *)pattern.expanded) > lenTripcode) {
		// Discard the expanded pattern because it's too long.
		
	} else if (pattern.remaining[0] == '^') {
		ERROR1(pattern.startsAtFirstChar,             ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
		ERROR1(strlen((char *)pattern.expanded) != 0, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
		pattern.startsAtFirstChar = TRUE;
		DISCARD_FIRST_N_CHARACTERS(pattern.remaining, 1);
 		PushRegexPattern(&pattern);
	
	} else if (pattern.remaining[strlen((char *)pattern.remaining) - 1] == '$') {
		int32_t len = strlen((char *)pattern.remaining);
		ERROR1(pattern.endsAtLastChar, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
		pattern.endsAtLastChar = TRUE;
		pattern.remaining[len - 1] = '\0';
 		PushRegexPattern(&pattern);
	
	} else if (!pattern.wereVerticalBarsProcessed) {
		ERROR1(strlen((char *)pattern.expanded) > 0, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
		//
		RegexPattern newPattern = pattern;
		int32_t start = 0, pos = 0, depth = 0;
		//
		newPattern.wereVerticalBarsProcessed = TRUE;
		while (pattern.remaining[pos] != '\0') {
			if (pattern.remaining[pos] == '(') {
				++depth;
			} else if (pattern.remaining[pos] == ')') {
				ERROR1(depth <= 0, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
				--depth;
			} else if (depth <= 0 && pattern.remaining[pos] == '|') {
				if (start < pos) {
					strncpy((char *)newPattern.remaining, (char *)pattern.remaining + start, pos - start);
					newPattern.remaining[pos - start] = '\0';
					PushRegexPattern(&newPattern);
				}
				start = pos + 1;
			}
			++pos;
		}
		if (start < pos) {
			strncpy((char *)newPattern.remaining, (char *)pattern.remaining + start, pos - start);
			newPattern.remaining[pos - start] = '\0';
			PushRegexPattern(&newPattern);
		}

	} else {
		unsigned char nextToken[MAX_LEN_TARGET_PATTERN + 1];
		int32_t   lenNextToken;
		
		// Obtain the next token.
		if (IS_BASE64_CHAR(pattern.remaining[0])) {
			nextToken[0] = pattern.remaining[0];
			nextToken[1] = '\0';
		} else if (pattern.remaining[0] == '(') {
			int32_t pos = 1, depth = 0;
			while (!(depth == 0 && pattern.remaining[pos] == ')')) {
				ERROR1(pattern.remaining[pos] == '\0', ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
				if (pattern.remaining[pos] == '(') {
					++depth;
				} else if (pattern.remaining[pos] == ')') {
					--depth;
				}
				++pos;
			}
			strncpy((char *)nextToken, (char *)pattern.remaining, pos + 1);
			nextToken[pos + 1] = '\0';
		} else if (pattern.remaining[0] == '[') {
			int32_t pos = 1;
			while (pattern.remaining[pos] != ']') {
				ERROR1(pattern.remaining[pos] == '\0', ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
				ERROR1(   !IS_BASE64_CHAR(pattern.remaining[pos]) 
				       && pattern.remaining[pos] != '^'
				       && pattern.remaining[pos] != '-'
				       && pattern.remaining[pos] != ':', ERROR_INVALID_REGEX, "Invalid regular expression: `%s'",
				       pattern.original);
				++pos;
			}
			strncpy((char *)nextToken, (char *)pattern.remaining, pos + 1);
			nextToken[pos + 1] = '\0';
		} else if (pattern.remaining[0] == '\\') {
			ERROR1(strlen((char *)pattern.remaining) < 2, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			nextToken[0] = '\\';
			nextToken[1] = pattern.remaining[1];
			nextToken[2] = '\0';
		} else {
			ERROR1(TRUE, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
		}
		lenNextToken = strlen((char *)nextToken);
		// printf("nextToken[] = `%s'\n", nextToken);

		if (   strlen((char *)pattern.remaining) > lenNextToken
			&& pattern.remaining[lenNextToken] == '*'          ) {
			//
			ERROR1(   strlen((char *)pattern.remaining) >= lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "**", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			ERROR1(   strlen((char *)pattern.remaining) >=  lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "*+", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			ERROR1(   strlen((char *)pattern.remaining) >=  lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "*?", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			RegexPattern newPattern1 = pattern;
			RegexPattern newPattern2 = pattern;
			unsigned char        tmp[MAX_LEN_TARGET_PATTERN + 1];
			//
			strcpy((char *)tmp, (char *)nextToken);
			strcat((char *)tmp, (char *)newPattern2.remaining);
			strcpy((char *)newPattern2.remaining, (char *)tmp);
			PushRegexPattern(&newPattern2);
			//
			DISCARD_FIRST_N_CHARACTERS(newPattern1.remaining, lenNextToken + 1); // Discard the next token AND '*'.
			PushRegexPattern(&newPattern1);
			
		} else if (   strlen((char *)pattern.remaining) > lenNextToken
				   && pattern.remaining[lenNextToken] == '+'          ) {
			ERROR1(   strlen((char *)pattern.remaining) >= lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "+*", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			ERROR1(   strlen((char *)pattern.remaining) >=  lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "++", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			ERROR1(   strlen((char *)pattern.remaining) >=  lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "+?", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			//
			RegexPattern newPattern1 = pattern;
			RegexPattern newPattern2 = pattern;
			unsigned char        tmp[MAX_LEN_TARGET_PATTERN + 1];
			//
			strcpy((char *)tmp, (char *)nextToken);
			strcat((char *)tmp, (char *)newPattern2.remaining);
			strcpy((char *)newPattern2.remaining, (char *)tmp);
			PushRegexPattern(&newPattern2);
			//
			strcpy((char *)tmp, (char *)nextToken);
			strcat((char *)tmp, (char *)newPattern1.remaining + lenNextToken + 1); // delete '+'
			strcpy((char *)newPattern1.remaining, (char *)tmp); // push back
			PushRegexPattern(&newPattern1);

		} else if (   strlen((char *)pattern.remaining) > lenNextToken
			&& pattern.remaining[lenNextToken] == '?'          ) {
			//
			ERROR1(   strlen((char *)pattern.remaining) >= lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "?*", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			ERROR1(   strlen((char *)pattern.remaining) >=  lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "?+", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			ERROR1(   strlen((char *)pattern.remaining) >=  lenNextToken + 2
				   && strncmp((char *)pattern.remaining + lenNextToken, "??", 2) == 0,
				   ERROR_INVALID_REGEX,
				   "Invalid regular expression: `%s'", pattern.original);
			RegexPattern newPattern1 = pattern;
			RegexPattern newPattern2 = pattern;
			unsigned char        tmp[MAX_LEN_TARGET_PATTERN + 1];
			//
			strcpy((char *)tmp, (char *)nextToken);
			strcat((char *)tmp, (char *)newPattern2.remaining + lenNextToken + 1); // delete '?'
			strcpy((char *)newPattern2.remaining, (char *)tmp);
			PushRegexPattern(&newPattern2);
			//
			DISCARD_FIRST_N_CHARACTERS(newPattern1.remaining,	lenNextToken + 1); // Discard the next token AND '?'.
			PushRegexPattern(&newPattern1);
			
		} else if (   strlen((char *)pattern.remaining) > lenNextToken
				   && pattern.remaining[lenNextToken] == '{'          ) {
			int32_t n = 0, m = 0, lenCurrentToken;
			if (strlen((char *)pattern.remaining) >= lenNextToken + 3
				&& isdigit(pattern.remaining[lenNextToken + 1])
				&& pattern.remaining[lenNextToken + 1] >= '1'        
				&& pattern.remaining[lenNextToken + 2] == '}'  ) {
				lenCurrentToken = 3;
				n = m = pattern.remaining[lenNextToken + 1] - '0';
			} else if (strlen((char *)pattern.remaining) >= lenNextToken + 4
				&& isdigit(pattern.remaining[lenNextToken + 1])
				&& isdigit(pattern.remaining[lenNextToken + 2])
				&& pattern.remaining[lenNextToken + 3] == '}'  ) {
				lenCurrentToken = 4;
				n = m = (pattern.remaining[lenNextToken + 1] - '0') * 10 + (pattern.remaining[lenNextToken + 2] - '0');
				ERROR1(n < 1 || n > lenTripcode, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			} else if (strlen((char *)pattern.remaining) >= lenNextToken + 5
				&& isdigit(pattern.remaining[lenNextToken + 1])
				&& pattern.remaining[lenNextToken + 2] == ','        
				&& isdigit(pattern.remaining[lenNextToken + 3])
				&& pattern.remaining[lenNextToken + 4] == '}'  ) {
				lenCurrentToken = 5;
				n = pattern.remaining[lenNextToken + 1] - '0';
				m = pattern.remaining[lenNextToken + 3] - '0';
				ERROR1(n < 1 || n > m, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			} else if (strlen((char *)pattern.remaining) >= lenNextToken + 6
				&& isdigit(pattern.remaining[lenNextToken + 1])
				&& pattern.remaining[lenNextToken + 2] == ','        
				&& isdigit(pattern.remaining[lenNextToken + 3])
				&& isdigit(pattern.remaining[lenNextToken + 4])
				&& pattern.remaining[lenNextToken + 5] == '}'  ) {
				lenCurrentToken = 6;
				n = pattern.remaining[lenNextToken + 1] - '0';
				m = (pattern.remaining[lenNextToken + 3] - '0') * 10 + (pattern.remaining[lenNextToken + 4] - '0');
				ERROR1(n > m || m > lenTripcode, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			} else if (strlen((char *)pattern.remaining) >= lenNextToken + 7
				&& isdigit(pattern.remaining[lenNextToken + 1])
				&& isdigit(pattern.remaining[lenNextToken + 2])
				&& pattern.remaining[lenNextToken + 3] == ','        
				&& isdigit(pattern.remaining[lenNextToken + 4])
				&& isdigit(pattern.remaining[lenNextToken + 5])
				&& pattern.remaining[lenNextToken + 6] == '}'  ) {
				lenCurrentToken = 7;
				n = (pattern.remaining[lenNextToken + 1] - '0') * 10 + (pattern.remaining[lenNextToken + 2] - '0');
				m = (pattern.remaining[lenNextToken + 4] - '0') * 10 + (pattern.remaining[lenNextToken + 5] - '0');
				ERROR1(n > m || m > lenTripcode, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			} else {
				ERROR1(TRUE, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			}
			// printf("{n, m, lenCurrentToken} = {%d, %d, %d}\n", n, m, lenCurrentToken);
			//
			RegexPattern  newPattern;
			unsigned char tmp[MAX_LEN_TARGET_PATTERN + 1];
			for (int32_t i = n; i <= m; ++i) {
				newPattern = pattern;
				tmp[0] = '\0';
				for (int32_t j = 0; j < i; ++j) {
					strcat((char *)tmp, (char *)nextToken);
					// printf("{i, j} = {%d, %d}\n", i, j);
				}
				strcat((char *)tmp, (char *)newPattern.remaining + lenNextToken + lenCurrentToken);
				strcpy((char *)newPattern.remaining, (char *)tmp);
				PushRegexPattern(&newPattern);
			}

		} else if (strcmp((char *)nextToken, ".") == 0) {
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, strlen((char *)nextToken));
			int32_t indexLastChar = strlen((char *)pattern.expanded);
			pattern.expanded[indexLastChar + 1] = '\0';
			if (pattern.depth > 0 && pattern.expandSpecialCharactersInParentheses) {
				for (unsigned char ch = 'A'; ch <= 'Z'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
				for (unsigned char ch = 'a'; ch <= 'z'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
				for (unsigned char ch = '0'; ch <= '9'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
				pattern.expanded[indexLastChar] = '.'; PushRegexPattern(&pattern);
				pattern.expanded[indexLastChar] = '/'; PushRegexPattern(&pattern);
			} else {
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_ALL; PushRegexPattern(&pattern); 
			} 
		
		} else if (strcmp((char *)nextToken, "[:digit:]") == 0 || strcmp((char *)nextToken, "[0-9]") == 0) {
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, strlen((char *)nextToken));
			int32_t indexLastChar = strlen((char *)pattern.expanded);
			pattern.expanded[indexLastChar + 1] = '\0';
			if (pattern.depth > 0 && pattern.expandSpecialCharactersInParentheses) {
				for (unsigned char ch = '0'; ch <= '9'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
			} else {
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_DIGIT;
				PushRegexPattern(&pattern);
			} 
		
		} else if (strcmp((char *)nextToken, "[:alpha:]") == 0 || strcmp((char *)nextToken, "[A-Za-z]") == 0 || strcmp((char *)nextToken, "[a-zA-Z]") == 0) {
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, strlen((char *)nextToken));
			int32_t indexLastChar = strlen((char *)pattern.expanded);
			pattern.expanded[indexLastChar + 1] = '\0';
			if (pattern.depth > 0 && pattern.expandSpecialCharactersInParentheses) {
				for (unsigned char ch = 'A'; ch <= 'Z'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
				for (unsigned char ch = 'a'; ch <= 'z'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
			} else {
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_UPPER; PushRegexPattern(&pattern); 
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_LOWER; PushRegexPattern(&pattern); 
			} 
		
		} else if (strcmp((char *)nextToken, "[:upper:]") == 0 || strcmp((char *)nextToken, "[A-Z]") == 0) {
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, strlen((char *)nextToken));
			int32_t indexLastChar = strlen((char *)pattern.expanded);
			pattern.expanded[indexLastChar + 1] = '\0';
			if (pattern.depth > 0 && pattern.expandSpecialCharactersInParentheses) {
				for (unsigned char ch = 'A'; ch <= 'Z'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
			} else {
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_UPPER;
				PushRegexPattern(&pattern); 
			} 

		} else if (strcmp((char *)nextToken, "[:lower:]") == 0 || strcmp((char *)nextToken, "[a-z]") == 0) {
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, strlen((char *)nextToken));
			int32_t indexLastChar = strlen((char *)pattern.expanded);
			pattern.expanded[indexLastChar + 1] = '\0';
			if (pattern.depth > 0 && pattern.expandSpecialCharactersInParentheses) {
				for (unsigned char ch = 'a'; ch <= 'z'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
			} else {
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_LOWER;
				PushRegexPattern(&pattern); 
			} 

		} else if (strcmp((char *)nextToken, "[:alnum:]") == 0) {
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, strlen((char *)nextToken));
			int32_t indexLastChar = strlen((char *)pattern.expanded);
			pattern.expanded[indexLastChar + 1] = '\0';
			if (pattern.depth > 0 && pattern.expandSpecialCharactersInParentheses) {
				for (unsigned char ch = 'A'; ch <= 'Z'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
				for (unsigned char ch = 'a'; ch <= 'z'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
				for (unsigned char ch = '0'; ch <= '9'; ++ch) {
					pattern.expanded[indexLastChar] = ch;
					PushRegexPattern(&pattern);
				}
			} else {
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_UPPER; PushRegexPattern(&pattern); 
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_LOWER; PushRegexPattern(&pattern); 
				pattern.expanded[indexLastChar] = SPECIAL_CHAR_DIGIT; PushRegexPattern(&pattern); 
			} 

		} else if (strcmp((char *)nextToken, "[:punct:]") == 0) {
			int32_t indexLastChar = strlen((char *)pattern.expanded);
			pattern.expanded[indexLastChar + 1] = '\0';
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, strlen("[:punct:]"));
			pattern.expanded[indexLastChar] = '.'; PushRegexPattern(&pattern);
			pattern.expanded[indexLastChar] = '/'; PushRegexPattern(&pattern);
		
		} else if (strlen((char *)pattern.remaining) >= 2 && pattern.remaining[0] == '\\' && isdigit(pattern.remaining[1])) { 
			ERROR1(pattern.remaining[1] == '0', ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			int32_t subexpressionIndex = pattern.remaining[1] - '1';
			// printf("subexpressionIndex: %d\n", subexpressionIndex);
			ERROR1(subexpressionIndex >= pattern.numSubexpressions || !pattern.wereSubexpressionsSet[subexpressionIndex],
				   ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			strcat((char *)pattern.expanded, (char *)pattern.subexpressions[subexpressionIndex]);
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, 2);
			PushRegexPattern(&pattern);

		} else if (strlen((char *)pattern.remaining) >= 2 && pattern.remaining[0] == '\\') { 
			ERROR1(!IS_BASE64_CHAR(pattern.remaining[1]), ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			int32_t lenExpanded = strlen((char *)pattern.expanded);
			pattern.expanded[lenExpanded    ] = pattern.remaining[1]; // skip '\\'
			pattern.expanded[lenExpanded + 1] = '\0';
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, 2);
			PushRegexPattern(&pattern);
		
		} else if (nextToken[0] == '[') {
			BOOL outputFlag[64], inverseMatching;
			int32_t     posNextToken;
			//
			// printf("nextToken[0] == '['\n");
			ERROR1(strlen((char *)nextToken) < 3, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			inverseMatching = (nextToken[1] == '^');
			ERROR1(inverseMatching && strlen((char *)nextToken) < 4, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
			for (int32_t i = 0; i < 64; ++i) outputFlag[i] = inverseMatching;
			posNextToken = (inverseMatching) ? (2) : (1);
			while (nextToken[posNextToken] != ']') {
				ERROR1(nextToken[posNextToken] == '\0',          ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
				ERROR1(!IS_BASE64_CHAR(nextToken[posNextToken]), ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
				if (nextToken[posNextToken + 1] != '-') {
					outputFlag[BASE64_CHAR_TO_INDEX(nextToken[posNextToken])] = !inverseMatching;
					++posNextToken;
				} else {
					unsigned char first = nextToken[posNextToken], last = nextToken[posNextToken + 2];
					ERROR1(last == '\0',                       ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
					ERROR1(!IS_BASE64_CHAR(last),              ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
					ERROR1(first == '.' || last == '.',        ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
					ERROR1(first == '/' || last == '/',        ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
					ERROR1(    ('A' <= first && first <= 'Z')
					       && !('A' <= last  && last  <= 'Z'), ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
					ERROR1(    ('a' <= first && first <= 'z')
					       && !('a' <= last  && last  <= 'z'), ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
					ERROR1(    ('0' <= first && first <= '9')
					       && !('0' <= last  && last  <= '9'), ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
					ERROR1(first > last,                       ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
					for (int32_t i = BASE64_CHAR_TO_INDEX(first); i <= BASE64_CHAR_TO_INDEX(last); ++i) {
						ASSERT(0 <= i && i < 64);
						outputFlag[i] = !inverseMatching;
					}
					posNextToken += 3;
				}
			}
			//
			int32_t indexExpanded = strlen((char *)pattern.expanded);
			pattern.expanded[indexExpanded + 1] = '\0';
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, strlen((char *)nextToken));
			for (int32_t i = 0; i < 64; ++i) {
				pattern.expanded[indexExpanded] = base64CharTable[i];
				if (outputFlag[i])
					PushRegexPattern(&pattern);
			}
					
		} else if (nextToken[0] == '(') {
			// nextToken[] = "( . . . )"
			int32_t start = 1, pos = 1, depthInNextToken = 0;
			//
			while (!(depthInNextToken <= 0 && nextToken[pos] == ')')) {
				if (nextToken[pos] == '(') {
					++depthInNextToken;
				} else if (nextToken[pos] == ')') {
					if (depthInNextToken <= 0)
						break;
					--depthInNextToken;
				} else if (depthInNextToken <= 0 && nextToken[pos] == '|') {
					if (start < pos) {
						RegexPattern newPattern = pattern;
						newPattern.expanded[0] = '\0';
						strncpy((char *)newPattern.remaining, (char *)nextToken + start, pos - start);
						newPattern.remaining[pos - start] = '\0';
						//
						newPattern.depth = pattern.depth + 1;
						ERROR1(newPattern.depth >= MAX_NUM_DEPTHS_IN_REGEX_PATTERN,
							   ERROR_INVALID_REGEX,
							   "The following regular expression is nested too deeply: `%s'",
							   pattern.original);
						strcpy((char *)newPattern.expandedAtLowerDepth[pattern.depth], (char *)pattern.expanded);
						strcpy((char *)newPattern.remainingAtLowerDepth[pattern.depth], (char *)pattern.remaining + strlen((char *)nextToken));
						if (newPattern.numSubexpressions < MAX_NUM_SUBEXPRESSIONS_IN_REGEX_PATTERN) {
							newPattern.subexpressions       [newPattern.numSubexpressions][0] = '\0';
							newPattern.wereSubexpressionsSet[newPattern.numSubexpressions]    = FALSE;
							newPattern.subexpressionIndexAtLowerDepth[pattern.depth]          = newPattern.numSubexpressions;
							++newPattern.numSubexpressions;
						} else {
							newPattern.subexpressionIndexAtLowerDepth[pattern.depth]          = -1;
						}
						PushRegexPattern(&newPattern);
					}
					start = pos + 1;
				}
				++pos;
			}
			if (start < pos) {
				RegexPattern newPattern = pattern;
				newPattern.expanded[0] = '\0';
				strncpy((char *)newPattern.remaining, (char *)nextToken + start, pos - start);
				newPattern.remaining[pos - start] = '\0';
				//
				newPattern.depth = pattern.depth + 1;
				// printf("newPattern.depth: %d\n", newPattern.depth);
				ERROR1(newPattern.depth >= MAX_NUM_DEPTHS_IN_REGEX_PATTERN,
						ERROR_INVALID_REGEX,
						"The following regular expression is nested too deeply: `%s'",
						pattern.original);
				strcpy((char *)newPattern.expandedAtLowerDepth[pattern.depth], (char *)pattern.expanded);
				strcpy((char *)newPattern.remainingAtLowerDepth[pattern.depth], (char *)pattern.remaining + strlen((char *)nextToken));
				if (newPattern.numSubexpressions < MAX_NUM_SUBEXPRESSIONS_IN_REGEX_PATTERN) {
					newPattern.subexpressions       [newPattern.numSubexpressions][0] = '\0';
					newPattern.wereSubexpressionsSet[newPattern.numSubexpressions]    = FALSE;
					newPattern.subexpressionIndexAtLowerDepth[pattern.depth]          = newPattern.numSubexpressions;
					++newPattern.numSubexpressions;
				} else {
					newPattern.subexpressionIndexAtLowerDepth[pattern.depth]          = -1;
				}
				// printf("pattern.depth = %d\n", pattern.depth);
				// printf("newPattern.remainingAtLowerDepth[pattern.depth]: `%s'\n", newPattern.remainingAtLowerDepth[pattern.depth]);
				PushRegexPattern(&newPattern);
			}

		} else if (IS_BASE64_CHAR(pattern.remaining[0])) {
			RegexPattern newPattern = pattern;
			int32_t lenExpanded = strlen((char *)pattern.expanded);
			pattern.expanded[lenExpanded    ] = pattern.remaining[0];
			pattern.expanded[lenExpanded + 1] = '\0';
			DISCARD_FIRST_N_CHARACTERS(pattern.remaining, 1);
			PushRegexPattern(&pattern);

		} else {
			ERROR1(TRUE, ERROR_INVALID_REGEX, "Invalid regular expression: `%s'", pattern.original);
		}
	}
}

void ExpandRegexPattern(unsigned char *regexPattern, BOOL displayProgress)
{
	RegexPattern pattern;
	char msg[80 + 1];
	int32_t  loopCount = 0, numProcessedStates = 0;
	// int32_t prevNumExpandedPattern = numExpandedPatterns;
	
	// printf("ExpandRegexPattern(): regexPattern = `%s'\n", regexPattern);

	strcpy((char *)pattern.original,  (char *)regexPattern);
	strcpy((char *)pattern.remaining, (char *)regexPattern);
	pattern.expanded[0]       = '\0';
	pattern.startsAtFirstChar = FALSE;
	pattern.endsAtLastChar    = FALSE;
	pattern.wereVerticalBarsProcessed = FALSE;
	pattern.depth = 0;
	for (int32_t depth = 0; depth < MAX_NUM_DEPTHS_IN_REGEX_PATTERN; ++depth) {
		pattern.expandedAtLowerDepth[depth][0] = '\0';
		pattern.remainingAtLowerDepth[depth][0] = '\0';
	}
	pattern.numSubexpressions = 0;
	for (int32_t i = 0; i < MAX_NUM_SUBEXPRESSIONS_IN_REGEX_PATTERN; ++i)
		pattern.subexpressions[i][0] = '\0';
	//
	pattern.expandSpecialCharactersInParentheses = FALSE;
	int32_t lenRegexPattern = strlen((char *)regexPattern);
	for (int32_t i = 0; i + 1 < lenRegexPattern; ++i) {
		if (regexPattern[i] == '\\' && isdigit(regexPattern[i + 1])) {
			pattern.expandSpecialCharactersInParentheses = TRUE;
			break;
		}
	}
	// printf("pattern.expandSpecialCharactersInParentheses: %d\n", (int32_t)pattern.expandSpecialCharactersInParentheses);
	PushRegexPattern(&pattern);
	
	if (displayProgress) {
		printf("  Expanding a regex pattern...");
		reset_cursor_pos(0);
	}

	while (numRegexPattern > 0 && !GetTerminationState()) {
		ProcessNextRegexPattern();
		++numProcessedStates;
		if (++loopCount >= 100000 && displayProgress) {
			// qsort(regexPatternArray, numRegexPattern, sizeof(regexPatternArray[0]), CompareRegexPattern);
			sprintf(msg, "Expanding a regex pattern... (%dM states; %dM expanded patterns)",
			    (int)(numProcessedStates / 1000000),
			    (int)(numExpandedPatterns / 1000000));
			printf("  %-77s", msg);
			reset_cursor_pos(0);
			loopCount = 0;
		}
	}
	
	if (regexPatternArray) {
		free(regexPatternArray);
		regexPatternArray = NULL;
		numRegexPattern = 0;
		sizeRegexPatternArray = 0;
	}

	if (displayProgress) {
		printf("%-79s", "");
		reset_cursor_pos(0);
	}

#if FALSE
	printf("  %dM states were processed.\n", numProcessedStates / 10000000);
#endif
}

void ExpandSpecialCharInExpandedPatternArray(int32_t i, int32_t j)
{
	int32_t k;
	ExpandedPattern newExpandedPattern;
	
	if (expandedPatternArray[i].c[j] == SPECIAL_CHAR_ALL) {
		newExpandedPattern = expandedPatternArray[i];
		expandedPatternArray[i].c[j] = '0';
		for (k = '1'; k <= '9'; ++k) {
			newExpandedPattern.c[j] = k;
			AddNewExpandedPattern(newExpandedPattern.c, expandedPatternArray[i].pos);
		}
		for (k = 'A'; k <= 'Z'; ++k) {
			newExpandedPattern.c[j] = k;
			AddNewExpandedPattern(newExpandedPattern.c, expandedPatternArray[i].pos);
		}
		for (k = 'a'; k <= 'z'; ++k) {
			newExpandedPattern.c[j] = k;
			AddNewExpandedPattern(newExpandedPattern.c, expandedPatternArray[i].pos);
		}
		newExpandedPattern.c[j] = '.';
		AddNewExpandedPattern(newExpandedPattern.c, expandedPatternArray[i].pos);
		newExpandedPattern.c[j] = '/';
		AddNewExpandedPattern(newExpandedPattern.c, expandedPatternArray[i].pos);
	} else if (expandedPatternArray[i].c[j] == SPECIAL_CHAR_DIGIT) {
		newExpandedPattern = expandedPatternArray[i];
		expandedPatternArray[i].c[j] = '0';
		for (k = '1'; k <= '9'; ++k) {
			newExpandedPattern.c[j] = k;
			AddNewExpandedPattern(newExpandedPattern.c, expandedPatternArray[i].pos);
		}
	} else if (expandedPatternArray[i].c[j] == SPECIAL_CHAR_UPPER) {
		newExpandedPattern = expandedPatternArray[i];
		expandedPatternArray[i].c[j] = 'A';
		for (k = 'B'; k <= 'Z'; ++k) {
			newExpandedPattern.c[j] = k;
			AddNewExpandedPattern(newExpandedPattern.c, expandedPatternArray[i].pos);
		}
	} else if (expandedPatternArray[i].c[j] == SPECIAL_CHAR_LOWER) {
		newExpandedPattern = expandedPatternArray[i];
		expandedPatternArray[i].c[j] = 'a';
		for (k = 'b'; k <= 'z'; ++k) {
			newExpandedPattern.c[j] = k;
			AddNewExpandedPattern(newExpandedPattern.c, expandedPatternArray[i].pos);
		}
	}
}

void RemoveInvalidExpandedPatterns()
{
	BOOL dirty;

	// Check the last character of each pattern to see if the pattern is valid.
	// This is necessary for 10 character tripcodes, for which certain characters
	// are not allowed as the last ones.
	do {
		dirty = FALSE;
		for (int32_t i = 0; i < numExpandedPatterns; ++i) {
			int32_t len = strlen((char *)expandedPatternArray[i].c);
			if (   expandedPatternArray[i].pos + len == lenTripcode
			    && !IS_SPECIAL_CHARACTER    (expandedPatternArray[i].c[len - 1])
			    && !IS_LAST_CHAR_OF_TRIPCODE(expandedPatternArray[i].c[len - 1])) {
				expandedPatternArray[i] = expandedPatternArray[numExpandedPatterns - 1];
				--numExpandedPatterns;
				dirty = TRUE;
			}
		}
		if (dirty) {
			qsort(expandedPatternArray, numExpandedPatterns, sizeof(expandedPatternArray[0]), CompareExpandedPatternExactly);
			numExpandedPatterns = uniq(expandedPatternArray, numExpandedPatterns, sizeof(expandedPatternArray[0]), CompareExpandedPatternExactly);
		}
	} while (dirty);
	ERROR0(numExpandedPatterns == 0, ERROR_NO_TARGET_PATTERNS, "No target patterns were found (1).");
}	

void LoadTargetPatterns(BOOL displayProgress)
{
	char     line[MAX_LEN_INPUT_LINE + 1];
	unsigned char    targetPattern[MAX_LEN_TARGET_PATTERN + 1];
	int32_t      lenTargetPattern;
	int32_t      patternCount = 0;
	
	line[MAX_LEN_INPUT_LINE] = '\0';

	if (displayProgress) {
		printf("PATTERN(S)\n");
		printf("==========\n");
	} else if (options.redirection) {
		printf("[patterns]\n");
	}

	if (   (searchDevice == SEARCH_DEVICE_CPU || searchDevice == SEARCH_DEVICE_GPU_AND_CPU)
		&& (   options.searchForHisekiOnCPU
	        || options.searchForKakuhiOnCPU
	        || options.searchForKaibunOnCPU
	        || options.searchForKagamiOnCPU
	        || options.searchForYamabikoOnCPU
	        || options.searchForSourenOnCPU  )) {
		searchForSpecialPatternsOnCPU = TRUE;
	}

	for (int32_t patternFileIndex = 0; patternFileIndex < numPatternFiles; ++patternFileIndex) {
		FILE *patternFile = fopen(patternFilePathArray[patternFileIndex], "r");
		ERROR1(patternFile == NULL, ERROR_PATTERN_FILE, "The pattern file `%s' could not be opened.", patternFilePathArray[patternFileIndex]);
		int32_t   ignoreDirectiveCount = 0;
		BOOL  isRegexUsed = FALSE;
		
		while (!feof(patternFile)) {
			fgets(line, sizeof(line), patternFile);
			if (feof(patternFile) /* && strlen(line) == 0 */)
				break;
			if (ferror(patternFile)){
				fclose(patternFile);
				ERROR0(TRUE, ERROR_PATTERN_FILE, "File read error.");
			}
			int32_t i = 0, j = 0;
			while (line[i] == ' ' || line[i] == '\t')
				++i;
		
			// Process a directive.
			if (line[i] == '#' || line[i] == '\n' || line[i] == '\r' || line[i] == '\0') {
				if (strncmp(line + i, "#ignore", strlen("#ignore")) == 0) {
					++ignoreDirectiveCount;
				} else if (strncmp(line + i, "#endignore", strlen("#endignore")) == 0) {
					ERROR0(ignoreDirectiveCount <= 0, ERROR_IGNORE_DIRECTIVE, "There is no \"#ignore\" matching \"#donotignore\".");
					--ignoreDirectiveCount;
				} else if (strncmp(line + i, "#regex", strlen("#regex")) == 0) {
					isRegexUsed = TRUE;
				} else if (strncmp(line + i, "#noregex", strlen("#noregex")) == 0) {
					isRegexUsed = FALSE;
				}
				continue;
			}
			if (ignoreDirectiveCount)
				continue;
			while (line[i]) {
				ERROR1(j >= MAX_LEN_TARGET_PATTERN, ERROR_PATTERN_TOO_LONG, "The target pattern `%s' is too long.", line);
				if (line[i] == '\n' || line[i] == '\r' || line[i] == ' ' || line[i] == '\t' || line[i] == '#' || line[i] == '\0')
					break;	
				targetPattern[j++] = line[i++];
			}
			targetPattern[j] = '\0';
			lenTargetPattern = strlen((char *)targetPattern);
			// Print the target pattern.
			if (displayProgress)
				printf("  %d: \"%s\"%s\n", patternCount, targetPattern, (isRegexUsed) ? " (regex)" : "");
			++patternCount;

			// Add entries to appropriate arrays.
			 if (isRegexUsed) {
				 if (options.redirection) {
					 printf("[regex],%s\n", targetPattern);
					 fflush(stdout);
				 }
				 ExpandRegexPattern(targetPattern, displayProgress);
			} else {
				ERROR1(lenTargetPattern < MIN_LEN_EXPANDED_PATTERN,
						ERROR_PATTERN_TOO_SHORT,
						"The target pattern `%s' is too short.",
						targetPattern);
				ERROR1(lenTargetPattern > lenTripcode,
						ERROR_PATTERN_TOO_LONG,
						"The target pattern `%s' is too long.",
						targetPattern);
				if (   lenTargetPattern < MIN_LEN_EXPANDED_PATTERN
					|| lenTargetPattern > lenTripcode)
					continue;
				for (i = 0; i < lenTargetPattern; ++i) {
					ERROR0(!IS_BASE64_CHAR(targetPattern[i]),
						   ERROR_INVALID_TARGET_PATTERN,
						   "There is an invalid character in a target pattern.");
				}
				AddNewExpandedPattern(targetPattern, 0);
			}
		}
		fclose(patternFile);
	}

#ifdef DEBUG_ADD_DUMMY_PATTERNS
	AddNewExpandedPattern((unsigned char *)"TEST/", 0);
#else
	ERROR0(numExpandedPatterns == 0, ERROR_NO_TARGET_PATTERNS, "No target patterns were found (0).");
#endif

	if (displayProgress) {
		printf("  Resolving collisions in the array of expanded patterns...                    ");
		reset_cursor_pos(0);
	} else if (options.redirection) {
		printf("[patterns]\n");
		fflush(stdout);
	}

	// Clean expandedPatternArray and
	// resolve collisions involving special characters.
	int32_t numCollisions = 0;
	BOOL dirty = TRUE;
	for (int32_t j = 0; j < lenTripcode; (!dirty) ? (++j) : (TRUE)) {
		if (dirty) {
			qsort(expandedPatternArray, numExpandedPatterns, sizeof(expandedPatternArray[0]), CompareExpandedPatternExactly);
			numExpandedPatterns = uniq(expandedPatternArray, numExpandedPatterns, sizeof(expandedPatternArray[0]), CompareExpandedPatternExactly);
			dirty = FALSE;
		}
		for (int32_t i = 0; i < numExpandedPatterns && !dirty; ++i) {
			if (   j < strlen((char *)expandedPatternArray[i].c)
			    && IS_SPECIAL_CHARACTER(expandedPatternArray[i].c[j])
				&& (   (   i > 0
					    && strlen((char *)expandedPatternArray[i - 1].c) > j
					    && expandedPatternArray[i].pos == expandedPatternArray[i - 1].pos
					    && IS_BASE64_CHAR(expandedPatternArray[i - 1].c[j])
					    && CompareSpecialCharacter(&(expandedPatternArray[i].c[j]), &(expandedPatternArray[i - 1].c[j])) == 0
					    && (j <= 0 || strncmp((char *)(expandedPatternArray[i].c), (char *)(expandedPatternArray[i - 1].c), j) == 0))
					|| (   i + 1 < numExpandedPatterns
					    && strlen((char *)expandedPatternArray[i + 1].c) > j
					    && expandedPatternArray[i].pos == expandedPatternArray[i + 1].pos
					    && IS_BASE64_CHAR(expandedPatternArray[i + 1].c[j])
					    && CompareSpecialCharacter(&(expandedPatternArray[i].c[j]), &(expandedPatternArray[i + 1].c[j])) == 0
					    && (j <= 0 || strncmp((char *)(expandedPatternArray[i].c), (char *)(expandedPatternArray[i + 1].c), j) == 0)))) {
				
				// There is a collision between two adjacent expanded patterns
				// due to the special character expandedPatternArray[i].c[j],
				// that is, the order of these two patterns cannot be determined
				// because of the special character. The following is an example of
				// such collisions:
				//     0: NUL@PO
				//     1: NULLPE
				// In this case, the order of these two strings is uncertain because of
				// the spcial character '@', or SPECIAL_CHAR_ALL. For instance,
				// "NULAPO", which matches "NUL@PO", is lesser than "NULLPE",
				// whereas "NULZPO", which also matches "NUL@PO", is greater than "NULLPE".
				// In order to resolve this "collision," the '@' must be "expanded."

				ExpandSpecialCharInExpandedPatternArray(i, j);
				dirty = TRUE;
				++numCollisions;
			}
		}
	}
	RemoveInvalidExpandedPatterns();

	// Set an appropriate search mode.	
	searchMode = SEARCH_MODE_NIL;
	for (int32_t i = 0; i < numExpandedPatterns; ++i) {
		if (expandedPatternArray[i].pos == 0) {
			// forward-matching pattern
			if (searchMode == SEARCH_MODE_NIL) {
				searchMode = SEARCH_MODE_FORWARD_MATCHING;
			} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING) {
				searchMode = SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING;
			}
		} else if (expandedPatternArray[i].pos + strlen((char *)(expandedPatternArray[i].c)) == lenTripcode) {
			// backward-matching pattern
			if (searchMode == SEARCH_MODE_NIL) {
				searchMode = SEARCH_MODE_BACKWARD_MATCHING;
			} else if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {
				searchMode = SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING;
			}
		} else {
			searchMode = SEARCH_MODE_FLEXIBLE;
			break;
		}
	}

	// Expand special characters that are used to create tripcode chunks.
	if (displayProgress) {
		printf("  Expanding special characters in the array of expanded patterns...            ");
		reset_cursor_pos(0);
	}
	for (int32_t i = 0; i < numExpandedPatterns; ++i) {
		if (   searchMode == SEARCH_MODE_FORWARD_MATCHING
		    || searchMode == SEARCH_MODE_FLEXIBLE
			|| expandedPatternArray[i].pos + strlen((char *)(expandedPatternArray[i].c)) != lenTripcode) {
			// Expand the first five characters.
			for (int32_t j = 0; j < MIN_LEN_EXPANDED_PATTERN; ++j)
				ExpandSpecialCharInExpandedPatternArray(i, j);
		} else {
			// Expand the last five characters.
			for (int32_t j = strlen((char *)expandedPatternArray[i].c) - MIN_LEN_EXPANDED_PATTERN;
			     j < strlen((char *)expandedPatternArray[i].c); ++j)
				ExpandSpecialCharInExpandedPatternArray(i, j);
		}
	}
	RemoveInvalidExpandedPatterns();
	qsort(expandedPatternArray, numExpandedPatterns, sizeof(expandedPatternArray[0]), CompareExpandedPatternExactly);
	numExpandedPatterns = uniq(expandedPatternArray, numExpandedPatterns, sizeof(expandedPatternArray[0]), CompareExpandedPatternExactly);

	// Remove redundant entries from expandedPatternArray[].
	if (displayProgress) {
		//      01234567890123456789012345678901234567890123456789012345678901234567890123456789
		printf("  Removing redundant expanded patterns...                                      ");
		reset_cursor_pos(0);
	}
	dirty = FALSE;
	do {
		if (dirty) {
			qsort(expandedPatternArray, numExpandedPatterns, sizeof(expandedPatternArray[0]), CompareExpandedPatternExactly);
			numExpandedPatterns = uniq(expandedPatternArray, numExpandedPatterns, sizeof(expandedPatternArray[0]), CompareExpandedPatternExactly);
			dirty = FALSE;
		}
		for (int32_t i = 0; i + 1 < numExpandedPatterns; ++i) {
			if (   expandedPatternArray[i].pos == expandedPatternArray[i + 1].pos
			    && strlen((char *)expandedPatternArray[i].c) <= strlen((char *)expandedPatternArray[i + 1].c)
			    && strncmp((char *)expandedPatternArray[i].c, (char *)expandedPatternArray[i + 1].c, strlen((char *)expandedPatternArray[i].c)) == 0) {
				// printf("Duplicate expanded patterns were found: '%s', '%s'.\n", expandedPatternArray[i].c, expandedPatternArray[i + 1].c);
				for (int32_t j = i + 1; j + 1 < numExpandedPatterns; ++j)
					expandedPatternArray[j] = expandedPatternArray[j + 1];
				--numExpandedPatterns;
				--i;
				dirty = TRUE;
				// break;
			}
		}
		if (displayProgress && dirty) {
			//      01234567890123456789012345678901234567890123456789012345678901234567890123456789
			printf("  Removing redundant expanded patterns... (%d expanded patterns)", numExpandedPatterns);
			reset_cursor_pos(0);
		}
	} while(dirty);

	// Create 30bit tripcode chunks and mark key bitmaps.
	if (displayProgress) {
		//      01234567890123456789012345678901234567890123456789012345678901234567890123456789
		printf("  Creating tripcode chunks and marking key bitmaps...                          ");
		reset_cursor_pos(0);
	}
	uint32_t tripcodeChunk;
	memset(chunkBitmap,       0x01, CHUNK_BITMAP_SIZE);
	memset(mediumChunkBitmap, 0x01, MEDIUM_CHUNK_BITMAP_SIZE);
	memset(smallChunkBitmap,  0x01, SMALL_CHUNK_BITMAP_SIZE);
	for (int32_t i = 0; i < numExpandedPatterns; ++i) {
		BOOL lastFiveCharacters =    (searchMode == SEARCH_MODE_BACKWARD_MATCHING || searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING)
					              && (expandedPatternArray[i].pos + strlen((char *)(expandedPatternArray[i].c)) == lenTripcode);
		ERROR0(!CreateTripcodeChunk(expandedPatternArray[i].c, &tripcodeChunk, lastFiveCharacters),
		       ERROR_INVALID_TARGET_PATTERN,
		       "There is an invalid character in a target pattern.");
		chunkBitmap      [tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING       ) * 6)] = 0x00;
		mediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)] = 0x00;
		smallChunkBitmap [tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING ) * 6)] = 0x00;
		AddNewTripcodeChunk(tripcodeChunk & 0x3fffffff);
	}
	qsort(tripcodeChunkArray, numTripcodeChunk, sizeof(uint32_t),                   CompareUINT32);
	numTripcodeChunk = uniq(tripcodeChunkArray, numTripcodeChunk, sizeof(uint32_t), CompareUINT32);
	ERROR0(numExpandedPatterns == 0, ERROR_NO_TARGET_PATTERNS, "No target patterns were found (2).");

	memset(compactMediumChunkBitmap,  0x00, COMPACT_MEDIUM_CHUNK_BITMAP_SIZE);
	for (int32_t i = 0; i < MEDIUM_CHUNK_BITMAP_SIZE; ++i)
		compactMediumChunkBitmap[i >> 3] |= (mediumChunkBitmap[i] ? (1 << (i & 7)) : 0);
	memset(compactSmallChunkBitmap,  0x00, COMPACT_SMALL_CHUNK_BITMAP_SIZE);
	for (int32_t i = 0; i < SMALL_CHUNK_BITMAP_SIZE; ++i)
		compactSmallChunkBitmap[i >> 3] |= (smallChunkBitmap[i] ? (1 << (i & 7)) : 0);

#ifdef DEBUG_DISPLAY_EXPANDED_PATTERNS
	for (int32_t i = 0; i < numExpandedPatterns; ++i)
		printf("expandedPatternArray[%6d] = {`%s', %d}\n", i, expandedPatternArray[i].c, expandedPatternArray[i].pos);
#endif
#ifdef DEBUG_DISPLAY_TRIPCODE_CHUNKS
	for (int32_t i = 0; i < numTripcodeChunk; ++i)
		printf("tripcodeChunkArray[%d] = 0x%08x\n", i, tripcodeChunkArray[i]);
	printf("numExpandedPatterns = %d\n", numExpandedPatterns);
	printf("numTripcodeChunk = %d\n", numTripcodeChunk);
#endif
	
	// Calculate the matching probability etc.
	if (displayProgress) {
		//      01234567890123456789012345678901234567890123456789012345678901234567890123456789
		printf("  Calculating the matching probability...                                      ");
		reset_cursor_pos(0);
	}
#define SIZE_PROBABILITY_ARRAY 72
	boost::multiprecision::number<boost::multiprecision::cpp_dec_float<128>> matchingProb_mpf, numAverageTrialsForOneMatch_mpf, p_mpf, q_mpf, probArray[SIZE_PROBABILITY_ARRAY];
	matchingProb_mpf = 0;
	minLenExpandedPattern = lenTripcode;
	maxLenExpandedPattern = 0; 
	for (int32_t i = 0; i < numExpandedPatterns; ++i) {
		int32_t len = strlen ((char *)expandedPatternArray[i].c);
		if (len < minLenExpandedPattern)
			minLenExpandedPattern = len;
		if (len > maxLenExpandedPattern)
			maxLenExpandedPattern = len;
		p_mpf = 1;
		for (int32_t j = 0; j < len; ++j) {
			if (lenTripcode == 10 && j == len - 1 && expandedPatternArray[i].pos + len == lenTripcode) {
				// The following are the only characters that may appear at the end of 10 character tripcodes:
				//     .26AEIMQUYcgkosw
				q_mpf =  (expandedPatternArray[i].c[j] == SPECIAL_CHAR_ALL  ) ? (16.0 / 16.0) :
						 (expandedPatternArray[i].c[j] == SPECIAL_CHAR_DIGIT) ? ( 2.0 / 16.0) :
						 (expandedPatternArray[i].c[j] == SPECIAL_CHAR_UPPER) ? ( 7.0 / 16.0) :
						 (expandedPatternArray[i].c[j] == SPECIAL_CHAR_LOWER) ? ( 6.0 / 16.0) :
				                                                                ( 1.0 / 16.0);
			} else {
				q_mpf =  (expandedPatternArray[i].c[j] == SPECIAL_CHAR_ALL  ) ? (64.0 / 64.0) :
						 (expandedPatternArray[i].c[j] == SPECIAL_CHAR_DIGIT) ? (10.0 / 64.0) :
						 (expandedPatternArray[i].c[j] == SPECIAL_CHAR_UPPER) ? (26.0 / 64.0) :
						 (expandedPatternArray[i].c[j] == SPECIAL_CHAR_LOWER) ? (26.0 / 64.0) :
				                                                                ( 1.0 / 64.0);
			}
			p_mpf *= q_mpf;
		}
		matchingProb_mpf += p_mpf;
	}
	matchingProb = (double)matchingProb_mpf;
	//
	int32_t   actualSizeProbArray = SIZE_PROBABILITY_ARRAY;
	probArray[0] = 1;
	probArray[0] -= matchingProb_mpf;
	for (int32_t i = 1; i < SIZE_PROBABILITY_ARRAY; ++i) {
		probArray[i] = probArray[i - 1] * probArray[i - 1];
		if (probArray[i] < 0.5) {
			actualSizeProbArray = i;
			break;
		}
	}
	numAverageTrialsForOneMatch_mpf = 0;
	p_mpf = 1;
	for (int32_t i = actualSizeProbArray - 1; i >= 0; --i) {
		q_mpf = p_mpf * probArray[i];
		while (q_mpf > 0.5) {
			p_mpf = q_mpf;
			q_mpf = pow(2.0L, i);
			numAverageTrialsForOneMatch_mpf += q_mpf;
			q_mpf = p_mpf * probArray[i];
		}
	}
	numAverageTrialsForOneMatch = (double)(numAverageTrialsForOneMatch_mpf);

#ifdef DEBUG_DISPLAY_NUM_COLLISIONS
	if (numCollisions) {
		printf("  %d collision%s resolved.         \n", numCollisions, (numCollisions == 1) ? " was" : "s were");
	} else {
		printf("  No collisions were found.        \n");
		// printf("                                  \n");
	}
#endif
	if (displayProgress) {
		//      01234567890123456789012345678901234567890123456789012345678901234567890123456789
		printf("                                                                               ");
		reset_cursor_pos(0);
		printf("\n");
	}
}

void ProcessMatch(unsigned char *tripcode, unsigned char *key)
{
	ERROR0(   (lenTripcode == 12 && !VerifySHA1Tripcode(tripcode, key))
	       || (lenTripcode == 10 && !VerifyDESTripcode (tripcode, key)),
			ERROR_TRIPCODE_VERIFICATION_FAILED,
			GetErrorMessage(ERROR_TRIPCODE_VERIFICATION_FAILED));
	if (!options.checkTripcodes || (!IsTripcodeDuplicate(tripcode) && IsValidKey((unsigned char *)key))) {
		ProcessValidTripcodePair(tripcode, key);
	} else {
		ProcessInvalidTripcodePair(tripcode, key);
	}
}

BOOL IsTripcodeChunkValid(unsigned char *tripcode)
{
	for (int32_t i = 0; i <= lenTripcode - 5; ++i) {
		uint32_t tripcodeChunk;
		CreateTripcodeChunk(tripcode + i, &tripcodeChunk, FALSE);
		if (0 < i && searchMode == SEARCH_MODE_FORWARD_MATCHING)
			continue;
		if (0 < i && i < lenTripcode - 5 && searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING)
			continue;
		if (i < lenTripcode - 5 && searchMode == SEARCH_MODE_BACKWARD_MATCHING)
			continue;
		if (   smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]
			&&      chunkBitmap[tripcodeChunk >> ((5 -       CHUNK_BITMAP_LEN_STRING) * 6)])
			continue;
		int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;                                            
		while (lower <= upper) {
			middle = (lower + upper) >> 1;                                                                      
			if (tripcodeChunk > tripcodeChunkArray[middle]) {                                  
				lower = middle + 1;                                                                             
			} else if (tripcodeChunk < tripcodeChunkArray[middle]) {                           
				upper = middle - 1;                                                                             
			} else {                                                                                            
				return TRUE;                                                                                          
			}                                                                                                   
		}                                                                                                       
	}
	return FALSE;
}

void ProcessPossibleMatch(unsigned char *tripcode, unsigned char *key)
{
#if FALSE
	printf("ProcessPossibleMatch(): tripcode[] = `%s'\n", tripcode);
	printf("ProcessPossibleMatch(): key[]      = `%s'\n", key);
#endif
#if FALSE
	BOOL dump = FALSE;
	if (strncmp((char *)(tripcode + 0), "TEST/", strlen("TEST/")) == 0) {
		printf("\`TEST/\' WAS FOUND (`%s').\n\a", tripcode);
		dump = TRUE;
	}
#endif
	for (int32_t pos = 0; pos < lenTripcode - LEN_TRIPCODE_CHUNK + 1 && pos + minLenExpandedPattern <= lenTripcode; ++pos) {
		for (int32_t lower = 0, upper = numExpandedPatterns -1; lower <= upper; ) {
			int32_t middle = (lower + upper) >> 1;
			int32_t lenExpandedPattern = strlen((char *)(expandedPatternArray[middle].c));
#if FALSE
			if (dump && strncmp((char *)expandedPatternArray[middle].c, "/TST/", strlen("/TST/")) == 0) {
				printf("  [lower = %2d, middle = %2d, upper = %2d]\n", lower, middle, upper);
				printf("    expandedPatternArray[middle].c = `%s'\n", expandedPatternArray[middle].c);
				printf("    lenExpandedPattern = %d\n", lenExpandedPattern);
				printf("    lenTripcode = %d\n", lenTripcode);
				printf("    pos = %d\n", pos);
				printf("    lenExpandedPattern > lenTripcode - pos = %d\n", lenExpandedPattern > lenTripcode - pos);
				printf("    expandedPatternArray[middle].pos > pos  = %d\n", expandedPatternArray[middle].pos > pos);
				printf("    expandedPatternArray[middle].pos == pos = %d\n", expandedPatternArray[middle].pos == pos);
				printf("    strncmp()                               = %d\n", strncmp((char *)(expandedPatternArray[middle].c), (char *)(tripcode + pos), lenExpandedPattern));
			}
#endif
			if (   expandedPatternArray[middle].pos > pos
				|| (   expandedPatternArray[middle].pos == pos
				    && lenExpandedPattern > lenTripcode - pos)
				|| (   expandedPatternArray[middle].pos == pos
					&& CompareStringWithSpecicalChar((expandedPatternArray[middle].c),
					                                 (tripcode + pos),
					                                 lenExpandedPattern                       ) > 0)){
				upper = middle - 1;
			} else if (    expandedPatternArray[middle].pos < pos 
					   || (   expandedPatternArray[middle].pos == pos
						   && CompareStringWithSpecicalChar((expandedPatternArray[middle].c),
						                                    (tripcode + pos),
						                                    lenExpandedPattern                       ) < 0)){
				lower = middle + 1;
			} else {
				ProcessMatch(tripcode, key);
				return;
			}
		}
	}
}
