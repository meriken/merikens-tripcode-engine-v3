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



#include "../MerikensTripcodeEngine.h"

#ifdef CUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE

#include "../CUDA10_Registers_Kernel_Common.h"

#define SALT 2048
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2049
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2050
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2051
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2052
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2053
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2054
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2055
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2056
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2057
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2058
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2059
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2060
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2061
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2062
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2063
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2064
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2065
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2066
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2067
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2068
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2069
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2070
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2071
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2072
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2073
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2074
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2075
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2076
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2077
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2078
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2079
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2080
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2081
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2082
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2083
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2084
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2085
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2086
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2087
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2088
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2089
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2090
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2091
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2092
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2093
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2094
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2095
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2096
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2097
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2098
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2099
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2100
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2101
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2102
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2103
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2104
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2105
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2106
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2107
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2108
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2109
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2110
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2111
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2112
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2113
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2114
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2115
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2116
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2117
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2118
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2119
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2120
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2121
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2122
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2123
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2124
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2125
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2126
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2127
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2128
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2129
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2130
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2131
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2132
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2133
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2134
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2135
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2136
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2137
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2138
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2139
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2140
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2141
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2142
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2143
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2144
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2145
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2146
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2147
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2148
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2149
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2150
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2151
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2152
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2153
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2154
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2155
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2156
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2157
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2158
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2159
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2160
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2161
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2162
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2163
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2164
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2165
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2166
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2167
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2168
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2169
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2170
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2171
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2172
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2173
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2174
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2175
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2176
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2177
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2178
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2179
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2180
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2181
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2182
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2183
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2184
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2185
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2186
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2187
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2188
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2189
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2190
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2191
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2192
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2193
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2194
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2195
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2196
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2197
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2198
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2199
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2200
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2201
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2202
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2203
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2204
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2205
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2206
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2207
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2208
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2209
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2210
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2211
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2212
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2213
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2214
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2215
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2216
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2217
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2218
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2219
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2220
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2221
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2222
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2223
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2224
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2225
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2226
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2227
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2228
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2229
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2230
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2231
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2232
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2233
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2234
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2235
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2236
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2237
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2238
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2239
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2240
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2241
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2242
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2243
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2244
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2245
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2246
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2247
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2248
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2249
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2250
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2251
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2252
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2253
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2254
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2255
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2256
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2257
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2258
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2259
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2260
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2261
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2262
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2263
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2264
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2265
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2266
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2267
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2268
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2269
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2270
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2271
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2272
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2273
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2274
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2275
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2276
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2277
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2278
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2279
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2280
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2281
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2282
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2283
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2284
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2285
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2286
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2287
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2288
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2289
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2290
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2291
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2292
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2293
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2294
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2295
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2296
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2297
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2298
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2299
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2300
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2301
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2302
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2303
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher8()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel8(
	uint32_t numBlocksPerGrid,
	cudaDeviceProp CUDADeviceProperties,
	cudaStream_t currentStream,
	unsigned char *cudaPassCountArray,
	unsigned char *cudaTripcodeIndexArray,
	uint32_t *cudaTripcodeChunkArray,
	uint32_t numTripcodeChunk,
	int32_t intSalt,
	unsigned char *cudaKey0Array,
	unsigned char *cudaKey7Array,
	DES_Vector *cudaKeyVectorsFrom49To55,
	unsigned char *cudaKeyAndRandomBytes,
	int32_t searchMode)
{
	dim3 dimGrid(numBlocksPerGrid);
	dim3 dimBlock(CUDA_DES_NUM_THREADS_PER_BLOCK);
	switch (intSalt) {
	case 2048: LAUNCH_KERNEL(2048); break;
	case 2049: LAUNCH_KERNEL(2049); break;
	case 2050: LAUNCH_KERNEL(2050); break;
	case 2051: LAUNCH_KERNEL(2051); break;
	case 2052: LAUNCH_KERNEL(2052); break;
	case 2053: LAUNCH_KERNEL(2053); break;
	case 2054: LAUNCH_KERNEL(2054); break;
	case 2055: LAUNCH_KERNEL(2055); break;
	case 2056: LAUNCH_KERNEL(2056); break;
	case 2057: LAUNCH_KERNEL(2057); break;
	case 2058: LAUNCH_KERNEL(2058); break;
	case 2059: LAUNCH_KERNEL(2059); break;
	case 2060: LAUNCH_KERNEL(2060); break;
	case 2061: LAUNCH_KERNEL(2061); break;
	case 2062: LAUNCH_KERNEL(2062); break;
	case 2063: LAUNCH_KERNEL(2063); break;
	case 2064: LAUNCH_KERNEL(2064); break;
	case 2065: LAUNCH_KERNEL(2065); break;
	case 2066: LAUNCH_KERNEL(2066); break;
	case 2067: LAUNCH_KERNEL(2067); break;
	case 2068: LAUNCH_KERNEL(2068); break;
	case 2069: LAUNCH_KERNEL(2069); break;
	case 2070: LAUNCH_KERNEL(2070); break;
	case 2071: LAUNCH_KERNEL(2071); break;
	case 2072: LAUNCH_KERNEL(2072); break;
	case 2073: LAUNCH_KERNEL(2073); break;
	case 2074: LAUNCH_KERNEL(2074); break;
	case 2075: LAUNCH_KERNEL(2075); break;
	case 2076: LAUNCH_KERNEL(2076); break;
	case 2077: LAUNCH_KERNEL(2077); break;
	case 2078: LAUNCH_KERNEL(2078); break;
	case 2079: LAUNCH_KERNEL(2079); break;
	case 2080: LAUNCH_KERNEL(2080); break;
	case 2081: LAUNCH_KERNEL(2081); break;
	case 2082: LAUNCH_KERNEL(2082); break;
	case 2083: LAUNCH_KERNEL(2083); break;
	case 2084: LAUNCH_KERNEL(2084); break;
	case 2085: LAUNCH_KERNEL(2085); break;
	case 2086: LAUNCH_KERNEL(2086); break;
	case 2087: LAUNCH_KERNEL(2087); break;
	case 2088: LAUNCH_KERNEL(2088); break;
	case 2089: LAUNCH_KERNEL(2089); break;
	case 2090: LAUNCH_KERNEL(2090); break;
	case 2091: LAUNCH_KERNEL(2091); break;
	case 2092: LAUNCH_KERNEL(2092); break;
	case 2093: LAUNCH_KERNEL(2093); break;
	case 2094: LAUNCH_KERNEL(2094); break;
	case 2095: LAUNCH_KERNEL(2095); break;
	case 2096: LAUNCH_KERNEL(2096); break;
	case 2097: LAUNCH_KERNEL(2097); break;
	case 2098: LAUNCH_KERNEL(2098); break;
	case 2099: LAUNCH_KERNEL(2099); break;
	case 2100: LAUNCH_KERNEL(2100); break;
	case 2101: LAUNCH_KERNEL(2101); break;
	case 2102: LAUNCH_KERNEL(2102); break;
	case 2103: LAUNCH_KERNEL(2103); break;
	case 2104: LAUNCH_KERNEL(2104); break;
	case 2105: LAUNCH_KERNEL(2105); break;
	case 2106: LAUNCH_KERNEL(2106); break;
	case 2107: LAUNCH_KERNEL(2107); break;
	case 2108: LAUNCH_KERNEL(2108); break;
	case 2109: LAUNCH_KERNEL(2109); break;
	case 2110: LAUNCH_KERNEL(2110); break;
	case 2111: LAUNCH_KERNEL(2111); break;
	case 2112: LAUNCH_KERNEL(2112); break;
	case 2113: LAUNCH_KERNEL(2113); break;
	case 2114: LAUNCH_KERNEL(2114); break;
	case 2115: LAUNCH_KERNEL(2115); break;
	case 2116: LAUNCH_KERNEL(2116); break;
	case 2117: LAUNCH_KERNEL(2117); break;
	case 2118: LAUNCH_KERNEL(2118); break;
	case 2119: LAUNCH_KERNEL(2119); break;
	case 2120: LAUNCH_KERNEL(2120); break;
	case 2121: LAUNCH_KERNEL(2121); break;
	case 2122: LAUNCH_KERNEL(2122); break;
	case 2123: LAUNCH_KERNEL(2123); break;
	case 2124: LAUNCH_KERNEL(2124); break;
	case 2125: LAUNCH_KERNEL(2125); break;
	case 2126: LAUNCH_KERNEL(2126); break;
	case 2127: LAUNCH_KERNEL(2127); break;
	case 2128: LAUNCH_KERNEL(2128); break;
	case 2129: LAUNCH_KERNEL(2129); break;
	case 2130: LAUNCH_KERNEL(2130); break;
	case 2131: LAUNCH_KERNEL(2131); break;
	case 2132: LAUNCH_KERNEL(2132); break;
	case 2133: LAUNCH_KERNEL(2133); break;
	case 2134: LAUNCH_KERNEL(2134); break;
	case 2135: LAUNCH_KERNEL(2135); break;
	case 2136: LAUNCH_KERNEL(2136); break;
	case 2137: LAUNCH_KERNEL(2137); break;
	case 2138: LAUNCH_KERNEL(2138); break;
	case 2139: LAUNCH_KERNEL(2139); break;
	case 2140: LAUNCH_KERNEL(2140); break;
	case 2141: LAUNCH_KERNEL(2141); break;
	case 2142: LAUNCH_KERNEL(2142); break;
	case 2143: LAUNCH_KERNEL(2143); break;
	case 2144: LAUNCH_KERNEL(2144); break;
	case 2145: LAUNCH_KERNEL(2145); break;
	case 2146: LAUNCH_KERNEL(2146); break;
	case 2147: LAUNCH_KERNEL(2147); break;
	case 2148: LAUNCH_KERNEL(2148); break;
	case 2149: LAUNCH_KERNEL(2149); break;
	case 2150: LAUNCH_KERNEL(2150); break;
	case 2151: LAUNCH_KERNEL(2151); break;
	case 2152: LAUNCH_KERNEL(2152); break;
	case 2153: LAUNCH_KERNEL(2153); break;
	case 2154: LAUNCH_KERNEL(2154); break;
	case 2155: LAUNCH_KERNEL(2155); break;
	case 2156: LAUNCH_KERNEL(2156); break;
	case 2157: LAUNCH_KERNEL(2157); break;
	case 2158: LAUNCH_KERNEL(2158); break;
	case 2159: LAUNCH_KERNEL(2159); break;
	case 2160: LAUNCH_KERNEL(2160); break;
	case 2161: LAUNCH_KERNEL(2161); break;
	case 2162: LAUNCH_KERNEL(2162); break;
	case 2163: LAUNCH_KERNEL(2163); break;
	case 2164: LAUNCH_KERNEL(2164); break;
	case 2165: LAUNCH_KERNEL(2165); break;
	case 2166: LAUNCH_KERNEL(2166); break;
	case 2167: LAUNCH_KERNEL(2167); break;
	case 2168: LAUNCH_KERNEL(2168); break;
	case 2169: LAUNCH_KERNEL(2169); break;
	case 2170: LAUNCH_KERNEL(2170); break;
	case 2171: LAUNCH_KERNEL(2171); break;
	case 2172: LAUNCH_KERNEL(2172); break;
	case 2173: LAUNCH_KERNEL(2173); break;
	case 2174: LAUNCH_KERNEL(2174); break;
	case 2175: LAUNCH_KERNEL(2175); break;
	case 2176: LAUNCH_KERNEL(2176); break;
	case 2177: LAUNCH_KERNEL(2177); break;
	case 2178: LAUNCH_KERNEL(2178); break;
	case 2179: LAUNCH_KERNEL(2179); break;
	case 2180: LAUNCH_KERNEL(2180); break;
	case 2181: LAUNCH_KERNEL(2181); break;
	case 2182: LAUNCH_KERNEL(2182); break;
	case 2183: LAUNCH_KERNEL(2183); break;
	case 2184: LAUNCH_KERNEL(2184); break;
	case 2185: LAUNCH_KERNEL(2185); break;
	case 2186: LAUNCH_KERNEL(2186); break;
	case 2187: LAUNCH_KERNEL(2187); break;
	case 2188: LAUNCH_KERNEL(2188); break;
	case 2189: LAUNCH_KERNEL(2189); break;
	case 2190: LAUNCH_KERNEL(2190); break;
	case 2191: LAUNCH_KERNEL(2191); break;
	case 2192: LAUNCH_KERNEL(2192); break;
	case 2193: LAUNCH_KERNEL(2193); break;
	case 2194: LAUNCH_KERNEL(2194); break;
	case 2195: LAUNCH_KERNEL(2195); break;
	case 2196: LAUNCH_KERNEL(2196); break;
	case 2197: LAUNCH_KERNEL(2197); break;
	case 2198: LAUNCH_KERNEL(2198); break;
	case 2199: LAUNCH_KERNEL(2199); break;
	case 2200: LAUNCH_KERNEL(2200); break;
	case 2201: LAUNCH_KERNEL(2201); break;
	case 2202: LAUNCH_KERNEL(2202); break;
	case 2203: LAUNCH_KERNEL(2203); break;
	case 2204: LAUNCH_KERNEL(2204); break;
	case 2205: LAUNCH_KERNEL(2205); break;
	case 2206: LAUNCH_KERNEL(2206); break;
	case 2207: LAUNCH_KERNEL(2207); break;
	case 2208: LAUNCH_KERNEL(2208); break;
	case 2209: LAUNCH_KERNEL(2209); break;
	case 2210: LAUNCH_KERNEL(2210); break;
	case 2211: LAUNCH_KERNEL(2211); break;
	case 2212: LAUNCH_KERNEL(2212); break;
	case 2213: LAUNCH_KERNEL(2213); break;
	case 2214: LAUNCH_KERNEL(2214); break;
	case 2215: LAUNCH_KERNEL(2215); break;
	case 2216: LAUNCH_KERNEL(2216); break;
	case 2217: LAUNCH_KERNEL(2217); break;
	case 2218: LAUNCH_KERNEL(2218); break;
	case 2219: LAUNCH_KERNEL(2219); break;
	case 2220: LAUNCH_KERNEL(2220); break;
	case 2221: LAUNCH_KERNEL(2221); break;
	case 2222: LAUNCH_KERNEL(2222); break;
	case 2223: LAUNCH_KERNEL(2223); break;
	case 2224: LAUNCH_KERNEL(2224); break;
	case 2225: LAUNCH_KERNEL(2225); break;
	case 2226: LAUNCH_KERNEL(2226); break;
	case 2227: LAUNCH_KERNEL(2227); break;
	case 2228: LAUNCH_KERNEL(2228); break;
	case 2229: LAUNCH_KERNEL(2229); break;
	case 2230: LAUNCH_KERNEL(2230); break;
	case 2231: LAUNCH_KERNEL(2231); break;
	case 2232: LAUNCH_KERNEL(2232); break;
	case 2233: LAUNCH_KERNEL(2233); break;
	case 2234: LAUNCH_KERNEL(2234); break;
	case 2235: LAUNCH_KERNEL(2235); break;
	case 2236: LAUNCH_KERNEL(2236); break;
	case 2237: LAUNCH_KERNEL(2237); break;
	case 2238: LAUNCH_KERNEL(2238); break;
	case 2239: LAUNCH_KERNEL(2239); break;
	case 2240: LAUNCH_KERNEL(2240); break;
	case 2241: LAUNCH_KERNEL(2241); break;
	case 2242: LAUNCH_KERNEL(2242); break;
	case 2243: LAUNCH_KERNEL(2243); break;
	case 2244: LAUNCH_KERNEL(2244); break;
	case 2245: LAUNCH_KERNEL(2245); break;
	case 2246: LAUNCH_KERNEL(2246); break;
	case 2247: LAUNCH_KERNEL(2247); break;
	case 2248: LAUNCH_KERNEL(2248); break;
	case 2249: LAUNCH_KERNEL(2249); break;
	case 2250: LAUNCH_KERNEL(2250); break;
	case 2251: LAUNCH_KERNEL(2251); break;
	case 2252: LAUNCH_KERNEL(2252); break;
	case 2253: LAUNCH_KERNEL(2253); break;
	case 2254: LAUNCH_KERNEL(2254); break;
	case 2255: LAUNCH_KERNEL(2255); break;
	case 2256: LAUNCH_KERNEL(2256); break;
	case 2257: LAUNCH_KERNEL(2257); break;
	case 2258: LAUNCH_KERNEL(2258); break;
	case 2259: LAUNCH_KERNEL(2259); break;
	case 2260: LAUNCH_KERNEL(2260); break;
	case 2261: LAUNCH_KERNEL(2261); break;
	case 2262: LAUNCH_KERNEL(2262); break;
	case 2263: LAUNCH_KERNEL(2263); break;
	case 2264: LAUNCH_KERNEL(2264); break;
	case 2265: LAUNCH_KERNEL(2265); break;
	case 2266: LAUNCH_KERNEL(2266); break;
	case 2267: LAUNCH_KERNEL(2267); break;
	case 2268: LAUNCH_KERNEL(2268); break;
	case 2269: LAUNCH_KERNEL(2269); break;
	case 2270: LAUNCH_KERNEL(2270); break;
	case 2271: LAUNCH_KERNEL(2271); break;
	case 2272: LAUNCH_KERNEL(2272); break;
	case 2273: LAUNCH_KERNEL(2273); break;
	case 2274: LAUNCH_KERNEL(2274); break;
	case 2275: LAUNCH_KERNEL(2275); break;
	case 2276: LAUNCH_KERNEL(2276); break;
	case 2277: LAUNCH_KERNEL(2277); break;
	case 2278: LAUNCH_KERNEL(2278); break;
	case 2279: LAUNCH_KERNEL(2279); break;
	case 2280: LAUNCH_KERNEL(2280); break;
	case 2281: LAUNCH_KERNEL(2281); break;
	case 2282: LAUNCH_KERNEL(2282); break;
	case 2283: LAUNCH_KERNEL(2283); break;
	case 2284: LAUNCH_KERNEL(2284); break;
	case 2285: LAUNCH_KERNEL(2285); break;
	case 2286: LAUNCH_KERNEL(2286); break;
	case 2287: LAUNCH_KERNEL(2287); break;
	case 2288: LAUNCH_KERNEL(2288); break;
	case 2289: LAUNCH_KERNEL(2289); break;
	case 2290: LAUNCH_KERNEL(2290); break;
	case 2291: LAUNCH_KERNEL(2291); break;
	case 2292: LAUNCH_KERNEL(2292); break;
	case 2293: LAUNCH_KERNEL(2293); break;
	case 2294: LAUNCH_KERNEL(2294); break;
	case 2295: LAUNCH_KERNEL(2295); break;
	case 2296: LAUNCH_KERNEL(2296); break;
	case 2297: LAUNCH_KERNEL(2297); break;
	case 2298: LAUNCH_KERNEL(2298); break;
	case 2299: LAUNCH_KERNEL(2299); break;
	case 2300: LAUNCH_KERNEL(2300); break;
	case 2301: LAUNCH_KERNEL(2301); break;
	case 2302: LAUNCH_KERNEL(2302); break;
	case 2303: LAUNCH_KERNEL(2303); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
