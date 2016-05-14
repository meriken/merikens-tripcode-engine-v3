// Meriken's Tripcode Engine 2.0.0
// Copyright (c) 2011-2015 Meriken.Z. <meriken.2ch@gmail.com>
//
// The initial versions of this software were based on:
// CUDA SHA-1 Tripper 0.2.1
// Copyright (c) 2009 Horo/.IBXjcg
// 
// The code that deals with DES decryption is partially adopted from:
// John the Ripper password cracker
// Copyright (c) 1996-2002, 2005, 2010 by Solar Designer
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



#include "MerikensTripcodeEngine.h"

#include "CUDA10_Registers_Kernel_Common.h"

#define SALT 0
#include "CUDA10_Kernel.h"
#define SALT 1
#include "CUDA10_Kernel.h"
#define SALT 2
#include "CUDA10_Kernel.h"
#define SALT 3
#include "CUDA10_Kernel.h"
#define SALT 4
#include "CUDA10_Kernel.h"
#define SALT 5
#include "CUDA10_Kernel.h"
#define SALT 6
#include "CUDA10_Kernel.h"
#define SALT 7
#include "CUDA10_Kernel.h"
#define SALT 8
#include "CUDA10_Kernel.h"
#define SALT 9
#include "CUDA10_Kernel.h"
#define SALT 10
#include "CUDA10_Kernel.h"
#define SALT 11
#include "CUDA10_Kernel.h"
#define SALT 12
#include "CUDA10_Kernel.h"
#define SALT 13
#include "CUDA10_Kernel.h"
#define SALT 14
#include "CUDA10_Kernel.h"
#define SALT 15
#include "CUDA10_Kernel.h"
#define SALT 16
#include "CUDA10_Kernel.h"
#define SALT 17
#include "CUDA10_Kernel.h"
#define SALT 18
#include "CUDA10_Kernel.h"
#define SALT 19
#include "CUDA10_Kernel.h"
#define SALT 20
#include "CUDA10_Kernel.h"
#define SALT 21
#include "CUDA10_Kernel.h"
#define SALT 22
#include "CUDA10_Kernel.h"
#define SALT 23
#include "CUDA10_Kernel.h"
#define SALT 24
#include "CUDA10_Kernel.h"
#define SALT 25
#include "CUDA10_Kernel.h"
#define SALT 26
#include "CUDA10_Kernel.h"
#define SALT 27
#include "CUDA10_Kernel.h"
#define SALT 28
#include "CUDA10_Kernel.h"
#define SALT 29
#include "CUDA10_Kernel.h"
#define SALT 30
#include "CUDA10_Kernel.h"
#define SALT 31
#include "CUDA10_Kernel.h"
#define SALT 32
#include "CUDA10_Kernel.h"
#define SALT 33
#include "CUDA10_Kernel.h"
#define SALT 34
#include "CUDA10_Kernel.h"
#define SALT 35
#include "CUDA10_Kernel.h"
#define SALT 36
#include "CUDA10_Kernel.h"
#define SALT 37
#include "CUDA10_Kernel.h"
#define SALT 38
#include "CUDA10_Kernel.h"
#define SALT 39
#include "CUDA10_Kernel.h"
#define SALT 40
#include "CUDA10_Kernel.h"
#define SALT 41
#include "CUDA10_Kernel.h"
#define SALT 42
#include "CUDA10_Kernel.h"
#define SALT 43
#include "CUDA10_Kernel.h"
#define SALT 44
#include "CUDA10_Kernel.h"
#define SALT 45
#include "CUDA10_Kernel.h"
#define SALT 46
#include "CUDA10_Kernel.h"
#define SALT 47
#include "CUDA10_Kernel.h"
#define SALT 48
#include "CUDA10_Kernel.h"
#define SALT 49
#include "CUDA10_Kernel.h"
#define SALT 50
#include "CUDA10_Kernel.h"
#define SALT 51
#include "CUDA10_Kernel.h"
#define SALT 52
#include "CUDA10_Kernel.h"
#define SALT 53
#include "CUDA10_Kernel.h"
#define SALT 54
#include "CUDA10_Kernel.h"
#define SALT 55
#include "CUDA10_Kernel.h"
#define SALT 56
#include "CUDA10_Kernel.h"
#define SALT 57
#include "CUDA10_Kernel.h"
#define SALT 58
#include "CUDA10_Kernel.h"
#define SALT 59
#include "CUDA10_Kernel.h"
#define SALT 60
#include "CUDA10_Kernel.h"
#define SALT 61
#include "CUDA10_Kernel.h"
#define SALT 62
#include "CUDA10_Kernel.h"
#define SALT 63
#include "CUDA10_Kernel.h"
#define SALT 64
#include "CUDA10_Kernel.h"
#define SALT 65
#include "CUDA10_Kernel.h"
#define SALT 66
#include "CUDA10_Kernel.h"
#define SALT 67
#include "CUDA10_Kernel.h"
#define SALT 68
#include "CUDA10_Kernel.h"
#define SALT 69
#include "CUDA10_Kernel.h"
#define SALT 70
#include "CUDA10_Kernel.h"
#define SALT 71
#include "CUDA10_Kernel.h"
#define SALT 72
#include "CUDA10_Kernel.h"
#define SALT 73
#include "CUDA10_Kernel.h"
#define SALT 74
#include "CUDA10_Kernel.h"
#define SALT 75
#include "CUDA10_Kernel.h"
#define SALT 76
#include "CUDA10_Kernel.h"
#define SALT 77
#include "CUDA10_Kernel.h"
#define SALT 78
#include "CUDA10_Kernel.h"
#define SALT 79
#include "CUDA10_Kernel.h"
#define SALT 80
#include "CUDA10_Kernel.h"
#define SALT 81
#include "CUDA10_Kernel.h"
#define SALT 82
#include "CUDA10_Kernel.h"
#define SALT 83
#include "CUDA10_Kernel.h"
#define SALT 84
#include "CUDA10_Kernel.h"
#define SALT 85
#include "CUDA10_Kernel.h"
#define SALT 86
#include "CUDA10_Kernel.h"
#define SALT 87
#include "CUDA10_Kernel.h"
#define SALT 88
#include "CUDA10_Kernel.h"
#define SALT 89
#include "CUDA10_Kernel.h"
#define SALT 90
#include "CUDA10_Kernel.h"
#define SALT 91
#include "CUDA10_Kernel.h"
#define SALT 92
#include "CUDA10_Kernel.h"
#define SALT 93
#include "CUDA10_Kernel.h"
#define SALT 94
#include "CUDA10_Kernel.h"
#define SALT 95
#include "CUDA10_Kernel.h"
#define SALT 96
#include "CUDA10_Kernel.h"
#define SALT 97
#include "CUDA10_Kernel.h"
#define SALT 98
#include "CUDA10_Kernel.h"
#define SALT 99
#include "CUDA10_Kernel.h"
#define SALT 100
#include "CUDA10_Kernel.h"
#define SALT 101
#include "CUDA10_Kernel.h"
#define SALT 102
#include "CUDA10_Kernel.h"
#define SALT 103
#include "CUDA10_Kernel.h"
#define SALT 104
#include "CUDA10_Kernel.h"
#define SALT 105
#include "CUDA10_Kernel.h"
#define SALT 106
#include "CUDA10_Kernel.h"
#define SALT 107
#include "CUDA10_Kernel.h"
#define SALT 108
#include "CUDA10_Kernel.h"
#define SALT 109
#include "CUDA10_Kernel.h"
#define SALT 110
#include "CUDA10_Kernel.h"
#define SALT 111
#include "CUDA10_Kernel.h"
#define SALT 112
#include "CUDA10_Kernel.h"
#define SALT 113
#include "CUDA10_Kernel.h"
#define SALT 114
#include "CUDA10_Kernel.h"
#define SALT 115
#include "CUDA10_Kernel.h"
#define SALT 116
#include "CUDA10_Kernel.h"
#define SALT 117
#include "CUDA10_Kernel.h"
#define SALT 118
#include "CUDA10_Kernel.h"
#define SALT 119
#include "CUDA10_Kernel.h"
#define SALT 120
#include "CUDA10_Kernel.h"
#define SALT 121
#include "CUDA10_Kernel.h"
#define SALT 122
#include "CUDA10_Kernel.h"
#define SALT 123
#include "CUDA10_Kernel.h"
#define SALT 124
#include "CUDA10_Kernel.h"
#define SALT 125
#include "CUDA10_Kernel.h"
#define SALT 126
#include "CUDA10_Kernel.h"
#define SALT 127
#include "CUDA10_Kernel.h"
#define SALT 128
#include "CUDA10_Kernel.h"
#define SALT 129
#include "CUDA10_Kernel.h"
#define SALT 130
#include "CUDA10_Kernel.h"
#define SALT 131
#include "CUDA10_Kernel.h"
#define SALT 132
#include "CUDA10_Kernel.h"
#define SALT 133
#include "CUDA10_Kernel.h"
#define SALT 134
#include "CUDA10_Kernel.h"
#define SALT 135
#include "CUDA10_Kernel.h"
#define SALT 136
#include "CUDA10_Kernel.h"
#define SALT 137
#include "CUDA10_Kernel.h"
#define SALT 138
#include "CUDA10_Kernel.h"
#define SALT 139
#include "CUDA10_Kernel.h"
#define SALT 140
#include "CUDA10_Kernel.h"
#define SALT 141
#include "CUDA10_Kernel.h"
#define SALT 142
#include "CUDA10_Kernel.h"
#define SALT 143
#include "CUDA10_Kernel.h"
#define SALT 144
#include "CUDA10_Kernel.h"
#define SALT 145
#include "CUDA10_Kernel.h"
#define SALT 146
#include "CUDA10_Kernel.h"
#define SALT 147
#include "CUDA10_Kernel.h"
#define SALT 148
#include "CUDA10_Kernel.h"
#define SALT 149
#include "CUDA10_Kernel.h"
#define SALT 150
#include "CUDA10_Kernel.h"
#define SALT 151
#include "CUDA10_Kernel.h"
#define SALT 152
#include "CUDA10_Kernel.h"
#define SALT 153
#include "CUDA10_Kernel.h"
#define SALT 154
#include "CUDA10_Kernel.h"
#define SALT 155
#include "CUDA10_Kernel.h"
#define SALT 156
#include "CUDA10_Kernel.h"
#define SALT 157
#include "CUDA10_Kernel.h"
#define SALT 158
#include "CUDA10_Kernel.h"
#define SALT 159
#include "CUDA10_Kernel.h"
#define SALT 160
#include "CUDA10_Kernel.h"
#define SALT 161
#include "CUDA10_Kernel.h"
#define SALT 162
#include "CUDA10_Kernel.h"
#define SALT 163
#include "CUDA10_Kernel.h"
#define SALT 164
#include "CUDA10_Kernel.h"
#define SALT 165
#include "CUDA10_Kernel.h"
#define SALT 166
#include "CUDA10_Kernel.h"
#define SALT 167
#include "CUDA10_Kernel.h"
#define SALT 168
#include "CUDA10_Kernel.h"
#define SALT 169
#include "CUDA10_Kernel.h"
#define SALT 170
#include "CUDA10_Kernel.h"
#define SALT 171
#include "CUDA10_Kernel.h"
#define SALT 172
#include "CUDA10_Kernel.h"
#define SALT 173
#include "CUDA10_Kernel.h"
#define SALT 174
#include "CUDA10_Kernel.h"
#define SALT 175
#include "CUDA10_Kernel.h"
#define SALT 176
#include "CUDA10_Kernel.h"
#define SALT 177
#include "CUDA10_Kernel.h"
#define SALT 178
#include "CUDA10_Kernel.h"
#define SALT 179
#include "CUDA10_Kernel.h"
#define SALT 180
#include "CUDA10_Kernel.h"
#define SALT 181
#include "CUDA10_Kernel.h"
#define SALT 182
#include "CUDA10_Kernel.h"
#define SALT 183
#include "CUDA10_Kernel.h"
#define SALT 184
#include "CUDA10_Kernel.h"
#define SALT 185
#include "CUDA10_Kernel.h"
#define SALT 186
#include "CUDA10_Kernel.h"
#define SALT 187
#include "CUDA10_Kernel.h"
#define SALT 188
#include "CUDA10_Kernel.h"
#define SALT 189
#include "CUDA10_Kernel.h"
#define SALT 190
#include "CUDA10_Kernel.h"
#define SALT 191
#include "CUDA10_Kernel.h"
#define SALT 192
#include "CUDA10_Kernel.h"
#define SALT 193
#include "CUDA10_Kernel.h"
#define SALT 194
#include "CUDA10_Kernel.h"
#define SALT 195
#include "CUDA10_Kernel.h"
#define SALT 196
#include "CUDA10_Kernel.h"
#define SALT 197
#include "CUDA10_Kernel.h"
#define SALT 198
#include "CUDA10_Kernel.h"
#define SALT 199
#include "CUDA10_Kernel.h"
#define SALT 200
#include "CUDA10_Kernel.h"
#define SALT 201
#include "CUDA10_Kernel.h"
#define SALT 202
#include "CUDA10_Kernel.h"
#define SALT 203
#include "CUDA10_Kernel.h"
#define SALT 204
#include "CUDA10_Kernel.h"
#define SALT 205
#include "CUDA10_Kernel.h"
#define SALT 206
#include "CUDA10_Kernel.h"
#define SALT 207
#include "CUDA10_Kernel.h"
#define SALT 208
#include "CUDA10_Kernel.h"
#define SALT 209
#include "CUDA10_Kernel.h"
#define SALT 210
#include "CUDA10_Kernel.h"
#define SALT 211
#include "CUDA10_Kernel.h"
#define SALT 212
#include "CUDA10_Kernel.h"
#define SALT 213
#include "CUDA10_Kernel.h"
#define SALT 214
#include "CUDA10_Kernel.h"
#define SALT 215
#include "CUDA10_Kernel.h"
#define SALT 216
#include "CUDA10_Kernel.h"
#define SALT 217
#include "CUDA10_Kernel.h"
#define SALT 218
#include "CUDA10_Kernel.h"
#define SALT 219
#include "CUDA10_Kernel.h"
#define SALT 220
#include "CUDA10_Kernel.h"
#define SALT 221
#include "CUDA10_Kernel.h"
#define SALT 222
#include "CUDA10_Kernel.h"
#define SALT 223
#include "CUDA10_Kernel.h"
#define SALT 224
#include "CUDA10_Kernel.h"
#define SALT 225
#include "CUDA10_Kernel.h"
#define SALT 226
#include "CUDA10_Kernel.h"
#define SALT 227
#include "CUDA10_Kernel.h"
#define SALT 228
#include "CUDA10_Kernel.h"
#define SALT 229
#include "CUDA10_Kernel.h"
#define SALT 230
#include "CUDA10_Kernel.h"
#define SALT 231
#include "CUDA10_Kernel.h"
#define SALT 232
#include "CUDA10_Kernel.h"
#define SALT 233
#include "CUDA10_Kernel.h"
#define SALT 234
#include "CUDA10_Kernel.h"
#define SALT 235
#include "CUDA10_Kernel.h"
#define SALT 236
#include "CUDA10_Kernel.h"
#define SALT 237
#include "CUDA10_Kernel.h"
#define SALT 238
#include "CUDA10_Kernel.h"
#define SALT 239
#include "CUDA10_Kernel.h"
#define SALT 240
#include "CUDA10_Kernel.h"
#define SALT 241
#include "CUDA10_Kernel.h"
#define SALT 242
#include "CUDA10_Kernel.h"
#define SALT 243
#include "CUDA10_Kernel.h"
#define SALT 244
#include "CUDA10_Kernel.h"
#define SALT 245
#include "CUDA10_Kernel.h"
#define SALT 246
#include "CUDA10_Kernel.h"
#define SALT 247
#include "CUDA10_Kernel.h"
#define SALT 248
#include "CUDA10_Kernel.h"
#define SALT 249
#include "CUDA10_Kernel.h"
#define SALT 250
#include "CUDA10_Kernel.h"
#define SALT 251
#include "CUDA10_Kernel.h"
#define SALT 252
#include "CUDA10_Kernel.h"
#define SALT 253
#include "CUDA10_Kernel.h"
#define SALT 254
#include "CUDA10_Kernel.h"
#define SALT 255
#include "CUDA10_Kernel.h"
#define SALT 256
#include "CUDA10_Kernel.h"
#define SALT 257
#include "CUDA10_Kernel.h"
#define SALT 258
#include "CUDA10_Kernel.h"
#define SALT 259
#include "CUDA10_Kernel.h"
#define SALT 260
#include "CUDA10_Kernel.h"
#define SALT 261
#include "CUDA10_Kernel.h"
#define SALT 262
#include "CUDA10_Kernel.h"
#define SALT 263
#include "CUDA10_Kernel.h"
#define SALT 264
#include "CUDA10_Kernel.h"
#define SALT 265
#include "CUDA10_Kernel.h"
#define SALT 266
#include "CUDA10_Kernel.h"
#define SALT 267
#include "CUDA10_Kernel.h"
#define SALT 268
#include "CUDA10_Kernel.h"
#define SALT 269
#include "CUDA10_Kernel.h"
#define SALT 270
#include "CUDA10_Kernel.h"
#define SALT 271
#include "CUDA10_Kernel.h"
#define SALT 272
#include "CUDA10_Kernel.h"
#define SALT 273
#include "CUDA10_Kernel.h"
#define SALT 274
#include "CUDA10_Kernel.h"
#define SALT 275
#include "CUDA10_Kernel.h"
#define SALT 276
#include "CUDA10_Kernel.h"
#define SALT 277
#include "CUDA10_Kernel.h"
#define SALT 278
#include "CUDA10_Kernel.h"
#define SALT 279
#include "CUDA10_Kernel.h"
#define SALT 280
#include "CUDA10_Kernel.h"
#define SALT 281
#include "CUDA10_Kernel.h"
#define SALT 282
#include "CUDA10_Kernel.h"
#define SALT 283
#include "CUDA10_Kernel.h"
#define SALT 284
#include "CUDA10_Kernel.h"
#define SALT 285
#include "CUDA10_Kernel.h"
#define SALT 286
#include "CUDA10_Kernel.h"
#define SALT 287
#include "CUDA10_Kernel.h"
#define SALT 288
#include "CUDA10_Kernel.h"
#define SALT 289
#include "CUDA10_Kernel.h"
#define SALT 290
#include "CUDA10_Kernel.h"
#define SALT 291
#include "CUDA10_Kernel.h"
#define SALT 292
#include "CUDA10_Kernel.h"
#define SALT 293
#include "CUDA10_Kernel.h"
#define SALT 294
#include "CUDA10_Kernel.h"
#define SALT 295
#include "CUDA10_Kernel.h"
#define SALT 296
#include "CUDA10_Kernel.h"
#define SALT 297
#include "CUDA10_Kernel.h"
#define SALT 298
#include "CUDA10_Kernel.h"
#define SALT 299
#include "CUDA10_Kernel.h"
#define SALT 300
#include "CUDA10_Kernel.h"
#define SALT 301
#include "CUDA10_Kernel.h"
#define SALT 302
#include "CUDA10_Kernel.h"
#define SALT 303
#include "CUDA10_Kernel.h"
#define SALT 304
#include "CUDA10_Kernel.h"
#define SALT 305
#include "CUDA10_Kernel.h"
#define SALT 306
#include "CUDA10_Kernel.h"
#define SALT 307
#include "CUDA10_Kernel.h"
#define SALT 308
#include "CUDA10_Kernel.h"
#define SALT 309
#include "CUDA10_Kernel.h"
#define SALT 310
#include "CUDA10_Kernel.h"
#define SALT 311
#include "CUDA10_Kernel.h"
#define SALT 312
#include "CUDA10_Kernel.h"
#define SALT 313
#include "CUDA10_Kernel.h"
#define SALT 314
#include "CUDA10_Kernel.h"
#define SALT 315
#include "CUDA10_Kernel.h"
#define SALT 316
#include "CUDA10_Kernel.h"
#define SALT 317
#include "CUDA10_Kernel.h"
#define SALT 318
#include "CUDA10_Kernel.h"
#define SALT 319
#include "CUDA10_Kernel.h"
#define SALT 320
#include "CUDA10_Kernel.h"
#define SALT 321
#include "CUDA10_Kernel.h"
#define SALT 322
#include "CUDA10_Kernel.h"
#define SALT 323
#include "CUDA10_Kernel.h"
#define SALT 324
#include "CUDA10_Kernel.h"
#define SALT 325
#include "CUDA10_Kernel.h"
#define SALT 326
#include "CUDA10_Kernel.h"
#define SALT 327
#include "CUDA10_Kernel.h"
#define SALT 328
#include "CUDA10_Kernel.h"
#define SALT 329
#include "CUDA10_Kernel.h"
#define SALT 330
#include "CUDA10_Kernel.h"
#define SALT 331
#include "CUDA10_Kernel.h"
#define SALT 332
#include "CUDA10_Kernel.h"
#define SALT 333
#include "CUDA10_Kernel.h"
#define SALT 334
#include "CUDA10_Kernel.h"
#define SALT 335
#include "CUDA10_Kernel.h"
#define SALT 336
#include "CUDA10_Kernel.h"
#define SALT 337
#include "CUDA10_Kernel.h"
#define SALT 338
#include "CUDA10_Kernel.h"
#define SALT 339
#include "CUDA10_Kernel.h"
#define SALT 340
#include "CUDA10_Kernel.h"
#define SALT 341
#include "CUDA10_Kernel.h"
#define SALT 342
#include "CUDA10_Kernel.h"
#define SALT 343
#include "CUDA10_Kernel.h"
#define SALT 344
#include "CUDA10_Kernel.h"
#define SALT 345
#include "CUDA10_Kernel.h"
#define SALT 346
#include "CUDA10_Kernel.h"
#define SALT 347
#include "CUDA10_Kernel.h"
#define SALT 348
#include "CUDA10_Kernel.h"
#define SALT 349
#include "CUDA10_Kernel.h"
#define SALT 350
#include "CUDA10_Kernel.h"
#define SALT 351
#include "CUDA10_Kernel.h"
#define SALT 352
#include "CUDA10_Kernel.h"
#define SALT 353
#include "CUDA10_Kernel.h"
#define SALT 354
#include "CUDA10_Kernel.h"
#define SALT 355
#include "CUDA10_Kernel.h"
#define SALT 356
#include "CUDA10_Kernel.h"
#define SALT 357
#include "CUDA10_Kernel.h"
#define SALT 358
#include "CUDA10_Kernel.h"
#define SALT 359
#include "CUDA10_Kernel.h"
#define SALT 360
#include "CUDA10_Kernel.h"
#define SALT 361
#include "CUDA10_Kernel.h"
#define SALT 362
#include "CUDA10_Kernel.h"
#define SALT 363
#include "CUDA10_Kernel.h"
#define SALT 364
#include "CUDA10_Kernel.h"
#define SALT 365
#include "CUDA10_Kernel.h"
#define SALT 366
#include "CUDA10_Kernel.h"
#define SALT 367
#include "CUDA10_Kernel.h"
#define SALT 368
#include "CUDA10_Kernel.h"
#define SALT 369
#include "CUDA10_Kernel.h"
#define SALT 370
#include "CUDA10_Kernel.h"
#define SALT 371
#include "CUDA10_Kernel.h"
#define SALT 372
#include "CUDA10_Kernel.h"
#define SALT 373
#include "CUDA10_Kernel.h"
#define SALT 374
#include "CUDA10_Kernel.h"
#define SALT 375
#include "CUDA10_Kernel.h"
#define SALT 376
#include "CUDA10_Kernel.h"
#define SALT 377
#include "CUDA10_Kernel.h"
#define SALT 378
#include "CUDA10_Kernel.h"
#define SALT 379
#include "CUDA10_Kernel.h"
#define SALT 380
#include "CUDA10_Kernel.h"
#define SALT 381
#include "CUDA10_Kernel.h"
#define SALT 382
#include "CUDA10_Kernel.h"
#define SALT 383
#include "CUDA10_Kernel.h"
#define SALT 384
#include "CUDA10_Kernel.h"
#define SALT 385
#include "CUDA10_Kernel.h"
#define SALT 386
#include "CUDA10_Kernel.h"
#define SALT 387
#include "CUDA10_Kernel.h"
#define SALT 388
#include "CUDA10_Kernel.h"
#define SALT 389
#include "CUDA10_Kernel.h"
#define SALT 390
#include "CUDA10_Kernel.h"
#define SALT 391
#include "CUDA10_Kernel.h"
#define SALT 392
#include "CUDA10_Kernel.h"
#define SALT 393
#include "CUDA10_Kernel.h"
#define SALT 394
#include "CUDA10_Kernel.h"
#define SALT 395
#include "CUDA10_Kernel.h"
#define SALT 396
#include "CUDA10_Kernel.h"
#define SALT 397
#include "CUDA10_Kernel.h"
#define SALT 398
#include "CUDA10_Kernel.h"
#define SALT 399
#include "CUDA10_Kernel.h"
#define SALT 400
#include "CUDA10_Kernel.h"
#define SALT 401
#include "CUDA10_Kernel.h"
#define SALT 402
#include "CUDA10_Kernel.h"
#define SALT 403
#include "CUDA10_Kernel.h"
#define SALT 404
#include "CUDA10_Kernel.h"
#define SALT 405
#include "CUDA10_Kernel.h"
#define SALT 406
#include "CUDA10_Kernel.h"
#define SALT 407
#include "CUDA10_Kernel.h"
#define SALT 408
#include "CUDA10_Kernel.h"
#define SALT 409
#include "CUDA10_Kernel.h"
#define SALT 410
#include "CUDA10_Kernel.h"
#define SALT 411
#include "CUDA10_Kernel.h"
#define SALT 412
#include "CUDA10_Kernel.h"
#define SALT 413
#include "CUDA10_Kernel.h"
#define SALT 414
#include "CUDA10_Kernel.h"
#define SALT 415
#include "CUDA10_Kernel.h"
#define SALT 416
#include "CUDA10_Kernel.h"
#define SALT 417
#include "CUDA10_Kernel.h"
#define SALT 418
#include "CUDA10_Kernel.h"
#define SALT 419
#include "CUDA10_Kernel.h"
#define SALT 420
#include "CUDA10_Kernel.h"
#define SALT 421
#include "CUDA10_Kernel.h"
#define SALT 422
#include "CUDA10_Kernel.h"
#define SALT 423
#include "CUDA10_Kernel.h"
#define SALT 424
#include "CUDA10_Kernel.h"
#define SALT 425
#include "CUDA10_Kernel.h"
#define SALT 426
#include "CUDA10_Kernel.h"
#define SALT 427
#include "CUDA10_Kernel.h"
#define SALT 428
#include "CUDA10_Kernel.h"
#define SALT 429
#include "CUDA10_Kernel.h"
#define SALT 430
#include "CUDA10_Kernel.h"
#define SALT 431
#include "CUDA10_Kernel.h"
#define SALT 432
#include "CUDA10_Kernel.h"
#define SALT 433
#include "CUDA10_Kernel.h"
#define SALT 434
#include "CUDA10_Kernel.h"
#define SALT 435
#include "CUDA10_Kernel.h"
#define SALT 436
#include "CUDA10_Kernel.h"
#define SALT 437
#include "CUDA10_Kernel.h"
#define SALT 438
#include "CUDA10_Kernel.h"
#define SALT 439
#include "CUDA10_Kernel.h"
#define SALT 440
#include "CUDA10_Kernel.h"
#define SALT 441
#include "CUDA10_Kernel.h"
#define SALT 442
#include "CUDA10_Kernel.h"
#define SALT 443
#include "CUDA10_Kernel.h"
#define SALT 444
#include "CUDA10_Kernel.h"
#define SALT 445
#include "CUDA10_Kernel.h"
#define SALT 446
#include "CUDA10_Kernel.h"
#define SALT 447
#include "CUDA10_Kernel.h"
#define SALT 448
#include "CUDA10_Kernel.h"
#define SALT 449
#include "CUDA10_Kernel.h"
#define SALT 450
#include "CUDA10_Kernel.h"
#define SALT 451
#include "CUDA10_Kernel.h"
#define SALT 452
#include "CUDA10_Kernel.h"
#define SALT 453
#include "CUDA10_Kernel.h"
#define SALT 454
#include "CUDA10_Kernel.h"
#define SALT 455
#include "CUDA10_Kernel.h"
#define SALT 456
#include "CUDA10_Kernel.h"
#define SALT 457
#include "CUDA10_Kernel.h"
#define SALT 458
#include "CUDA10_Kernel.h"
#define SALT 459
#include "CUDA10_Kernel.h"
#define SALT 460
#include "CUDA10_Kernel.h"
#define SALT 461
#include "CUDA10_Kernel.h"
#define SALT 462
#include "CUDA10_Kernel.h"
#define SALT 463
#include "CUDA10_Kernel.h"
#define SALT 464
#include "CUDA10_Kernel.h"
#define SALT 465
#include "CUDA10_Kernel.h"
#define SALT 466
#include "CUDA10_Kernel.h"
#define SALT 467
#include "CUDA10_Kernel.h"
#define SALT 468
#include "CUDA10_Kernel.h"
#define SALT 469
#include "CUDA10_Kernel.h"
#define SALT 470
#include "CUDA10_Kernel.h"
#define SALT 471
#include "CUDA10_Kernel.h"
#define SALT 472
#include "CUDA10_Kernel.h"
#define SALT 473
#include "CUDA10_Kernel.h"
#define SALT 474
#include "CUDA10_Kernel.h"
#define SALT 475
#include "CUDA10_Kernel.h"
#define SALT 476
#include "CUDA10_Kernel.h"
#define SALT 477
#include "CUDA10_Kernel.h"
#define SALT 478
#include "CUDA10_Kernel.h"
#define SALT 479
#include "CUDA10_Kernel.h"
#define SALT 480
#include "CUDA10_Kernel.h"
#define SALT 481
#include "CUDA10_Kernel.h"
#define SALT 482
#include "CUDA10_Kernel.h"
#define SALT 483
#include "CUDA10_Kernel.h"
#define SALT 484
#include "CUDA10_Kernel.h"
#define SALT 485
#include "CUDA10_Kernel.h"
#define SALT 486
#include "CUDA10_Kernel.h"
#define SALT 487
#include "CUDA10_Kernel.h"
#define SALT 488
#include "CUDA10_Kernel.h"
#define SALT 489
#include "CUDA10_Kernel.h"
#define SALT 490
#include "CUDA10_Kernel.h"
#define SALT 491
#include "CUDA10_Kernel.h"
#define SALT 492
#include "CUDA10_Kernel.h"
#define SALT 493
#include "CUDA10_Kernel.h"
#define SALT 494
#include "CUDA10_Kernel.h"
#define SALT 495
#include "CUDA10_Kernel.h"
#define SALT 496
#include "CUDA10_Kernel.h"
#define SALT 497
#include "CUDA10_Kernel.h"
#define SALT 498
#include "CUDA10_Kernel.h"
#define SALT 499
#include "CUDA10_Kernel.h"
#define SALT 500
#include "CUDA10_Kernel.h"
#define SALT 501
#include "CUDA10_Kernel.h"
#define SALT 502
#include "CUDA10_Kernel.h"
#define SALT 503
#include "CUDA10_Kernel.h"
#define SALT 504
#include "CUDA10_Kernel.h"
#define SALT 505
#include "CUDA10_Kernel.h"
#define SALT 506
#include "CUDA10_Kernel.h"
#define SALT 507
#include "CUDA10_Kernel.h"
#define SALT 508
#include "CUDA10_Kernel.h"
#define SALT 509
#include "CUDA10_Kernel.h"
#define SALT 510
#include "CUDA10_Kernel.h"
#define SALT 511
#include "CUDA10_Kernel.h"



void CUDA_DES_InitializeKernelLauncher0()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactSmallKeyBitmap, compactSmallKeyBitmap, sizeof(unsigned char) * COMPACT_SMALL_KEY_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
}

void CUDA_DES_LaunchKernel0(
	dim3 dimGrid, 
	dim3 dimBlock,
	cudaDeviceProp CUDADeviceProperties,
	cudaStream_t currentStream,
	unsigned char *cudaPassCountArray,
	unsigned char *cudaTripcodeIndexArray,
	unsigned char *cudaKeyBitmap,
	unsigned int *cudaTripcodeChunkArray,
	unsigned int numTripcodeChunk,
	int intSalt,
	unsigned char *cudaKey0Array,
	unsigned char *cudaKey7Array,
	DES_Vector *cudaKeyVectorsFrom49To55,
	unsigned char *cudaKeyAndRandomBytes,
	int searchMode)
{
	switch (intSalt) {
		case 0: LAUNCH_KERNEL(0); break;
		case 1: LAUNCH_KERNEL(1); break;
		case 2: LAUNCH_KERNEL(2); break;
		case 3: LAUNCH_KERNEL(3); break;
		case 4: LAUNCH_KERNEL(4); break;
		case 5: LAUNCH_KERNEL(5); break;
		case 6: LAUNCH_KERNEL(6); break;
		case 7: LAUNCH_KERNEL(7); break;
		case 8: LAUNCH_KERNEL(8); break;
		case 9: LAUNCH_KERNEL(9); break;
		case 10: LAUNCH_KERNEL(10); break;
		case 11: LAUNCH_KERNEL(11); break;
		case 12: LAUNCH_KERNEL(12); break;
		case 13: LAUNCH_KERNEL(13); break;
		case 14: LAUNCH_KERNEL(14); break;
		case 15: LAUNCH_KERNEL(15); break;
		case 16: LAUNCH_KERNEL(16); break;
		case 17: LAUNCH_KERNEL(17); break;
		case 18: LAUNCH_KERNEL(18); break;
		case 19: LAUNCH_KERNEL(19); break;
		case 20: LAUNCH_KERNEL(20); break;
		case 21: LAUNCH_KERNEL(21); break;
		case 22: LAUNCH_KERNEL(22); break;
		case 23: LAUNCH_KERNEL(23); break;
		case 24: LAUNCH_KERNEL(24); break;
		case 25: LAUNCH_KERNEL(25); break;
		case 26: LAUNCH_KERNEL(26); break;
		case 27: LAUNCH_KERNEL(27); break;
		case 28: LAUNCH_KERNEL(28); break;
		case 29: LAUNCH_KERNEL(29); break;
		case 30: LAUNCH_KERNEL(30); break;
		case 31: LAUNCH_KERNEL(31); break;
		case 32: LAUNCH_KERNEL(32); break;
		case 33: LAUNCH_KERNEL(33); break;
		case 34: LAUNCH_KERNEL(34); break;
		case 35: LAUNCH_KERNEL(35); break;
		case 36: LAUNCH_KERNEL(36); break;
		case 37: LAUNCH_KERNEL(37); break;
		case 38: LAUNCH_KERNEL(38); break;
		case 39: LAUNCH_KERNEL(39); break;
		case 40: LAUNCH_KERNEL(40); break;
		case 41: LAUNCH_KERNEL(41); break;
		case 42: LAUNCH_KERNEL(42); break;
		case 43: LAUNCH_KERNEL(43); break;
		case 44: LAUNCH_KERNEL(44); break;
		case 45: LAUNCH_KERNEL(45); break;
		case 46: LAUNCH_KERNEL(46); break;
		case 47: LAUNCH_KERNEL(47); break;
		case 48: LAUNCH_KERNEL(48); break;
		case 49: LAUNCH_KERNEL(49); break;
		case 50: LAUNCH_KERNEL(50); break;
		case 51: LAUNCH_KERNEL(51); break;
		case 52: LAUNCH_KERNEL(52); break;
		case 53: LAUNCH_KERNEL(53); break;
		case 54: LAUNCH_KERNEL(54); break;
		case 55: LAUNCH_KERNEL(55); break;
		case 56: LAUNCH_KERNEL(56); break;
		case 57: LAUNCH_KERNEL(57); break;
		case 58: LAUNCH_KERNEL(58); break;
		case 59: LAUNCH_KERNEL(59); break;
		case 60: LAUNCH_KERNEL(60); break;
		case 61: LAUNCH_KERNEL(61); break;
		case 62: LAUNCH_KERNEL(62); break;
		case 63: LAUNCH_KERNEL(63); break;
		case 64: LAUNCH_KERNEL(64); break;
		case 65: LAUNCH_KERNEL(65); break;
		case 66: LAUNCH_KERNEL(66); break;
		case 67: LAUNCH_KERNEL(67); break;
		case 68: LAUNCH_KERNEL(68); break;
		case 69: LAUNCH_KERNEL(69); break;
		case 70: LAUNCH_KERNEL(70); break;
		case 71: LAUNCH_KERNEL(71); break;
		case 72: LAUNCH_KERNEL(72); break;
		case 73: LAUNCH_KERNEL(73); break;
		case 74: LAUNCH_KERNEL(74); break;
		case 75: LAUNCH_KERNEL(75); break;
		case 76: LAUNCH_KERNEL(76); break;
		case 77: LAUNCH_KERNEL(77); break;
		case 78: LAUNCH_KERNEL(78); break;
		case 79: LAUNCH_KERNEL(79); break;
		case 80: LAUNCH_KERNEL(80); break;
		case 81: LAUNCH_KERNEL(81); break;
		case 82: LAUNCH_KERNEL(82); break;
		case 83: LAUNCH_KERNEL(83); break;
		case 84: LAUNCH_KERNEL(84); break;
		case 85: LAUNCH_KERNEL(85); break;
		case 86: LAUNCH_KERNEL(86); break;
		case 87: LAUNCH_KERNEL(87); break;
		case 88: LAUNCH_KERNEL(88); break;
		case 89: LAUNCH_KERNEL(89); break;
		case 90: LAUNCH_KERNEL(90); break;
		case 91: LAUNCH_KERNEL(91); break;
		case 92: LAUNCH_KERNEL(92); break;
		case 93: LAUNCH_KERNEL(93); break;
		case 94: LAUNCH_KERNEL(94); break;
		case 95: LAUNCH_KERNEL(95); break;
		case 96: LAUNCH_KERNEL(96); break;
		case 97: LAUNCH_KERNEL(97); break;
		case 98: LAUNCH_KERNEL(98); break;
		case 99: LAUNCH_KERNEL(99); break;
		case 100: LAUNCH_KERNEL(100); break;
		case 101: LAUNCH_KERNEL(101); break;
		case 102: LAUNCH_KERNEL(102); break;
		case 103: LAUNCH_KERNEL(103); break;
		case 104: LAUNCH_KERNEL(104); break;
		case 105: LAUNCH_KERNEL(105); break;
		case 106: LAUNCH_KERNEL(106); break;
		case 107: LAUNCH_KERNEL(107); break;
		case 108: LAUNCH_KERNEL(108); break;
		case 109: LAUNCH_KERNEL(109); break;
		case 110: LAUNCH_KERNEL(110); break;
		case 111: LAUNCH_KERNEL(111); break;
		case 112: LAUNCH_KERNEL(112); break;
		case 113: LAUNCH_KERNEL(113); break;
		case 114: LAUNCH_KERNEL(114); break;
		case 115: LAUNCH_KERNEL(115); break;
		case 116: LAUNCH_KERNEL(116); break;
		case 117: LAUNCH_KERNEL(117); break;
		case 118: LAUNCH_KERNEL(118); break;
		case 119: LAUNCH_KERNEL(119); break;
		case 120: LAUNCH_KERNEL(120); break;
		case 121: LAUNCH_KERNEL(121); break;
		case 122: LAUNCH_KERNEL(122); break;
		case 123: LAUNCH_KERNEL(123); break;
		case 124: LAUNCH_KERNEL(124); break;
		case 125: LAUNCH_KERNEL(125); break;
		case 126: LAUNCH_KERNEL(126); break;
		case 127: LAUNCH_KERNEL(127); break;
		case 128: LAUNCH_KERNEL(128); break;
		case 129: LAUNCH_KERNEL(129); break;
		case 130: LAUNCH_KERNEL(130); break;
		case 131: LAUNCH_KERNEL(131); break;
		case 132: LAUNCH_KERNEL(132); break;
		case 133: LAUNCH_KERNEL(133); break;
		case 134: LAUNCH_KERNEL(134); break;
		case 135: LAUNCH_KERNEL(135); break;
		case 136: LAUNCH_KERNEL(136); break;
		case 137: LAUNCH_KERNEL(137); break;
		case 138: LAUNCH_KERNEL(138); break;
		case 139: LAUNCH_KERNEL(139); break;
		case 140: LAUNCH_KERNEL(140); break;
		case 141: LAUNCH_KERNEL(141); break;
		case 142: LAUNCH_KERNEL(142); break;
		case 143: LAUNCH_KERNEL(143); break;
		case 144: LAUNCH_KERNEL(144); break;
		case 145: LAUNCH_KERNEL(145); break;
		case 146: LAUNCH_KERNEL(146); break;
		case 147: LAUNCH_KERNEL(147); break;
		case 148: LAUNCH_KERNEL(148); break;
		case 149: LAUNCH_KERNEL(149); break;
		case 150: LAUNCH_KERNEL(150); break;
		case 151: LAUNCH_KERNEL(151); break;
		case 152: LAUNCH_KERNEL(152); break;
		case 153: LAUNCH_KERNEL(153); break;
		case 154: LAUNCH_KERNEL(154); break;
		case 155: LAUNCH_KERNEL(155); break;
		case 156: LAUNCH_KERNEL(156); break;
		case 157: LAUNCH_KERNEL(157); break;
		case 158: LAUNCH_KERNEL(158); break;
		case 159: LAUNCH_KERNEL(159); break;
		case 160: LAUNCH_KERNEL(160); break;
		case 161: LAUNCH_KERNEL(161); break;
		case 162: LAUNCH_KERNEL(162); break;
		case 163: LAUNCH_KERNEL(163); break;
		case 164: LAUNCH_KERNEL(164); break;
		case 165: LAUNCH_KERNEL(165); break;
		case 166: LAUNCH_KERNEL(166); break;
		case 167: LAUNCH_KERNEL(167); break;
		case 168: LAUNCH_KERNEL(168); break;
		case 169: LAUNCH_KERNEL(169); break;
		case 170: LAUNCH_KERNEL(170); break;
		case 171: LAUNCH_KERNEL(171); break;
		case 172: LAUNCH_KERNEL(172); break;
		case 173: LAUNCH_KERNEL(173); break;
		case 174: LAUNCH_KERNEL(174); break;
		case 175: LAUNCH_KERNEL(175); break;
		case 176: LAUNCH_KERNEL(176); break;
		case 177: LAUNCH_KERNEL(177); break;
		case 178: LAUNCH_KERNEL(178); break;
		case 179: LAUNCH_KERNEL(179); break;
		case 180: LAUNCH_KERNEL(180); break;
		case 181: LAUNCH_KERNEL(181); break;
		case 182: LAUNCH_KERNEL(182); break;
		case 183: LAUNCH_KERNEL(183); break;
		case 184: LAUNCH_KERNEL(184); break;
		case 185: LAUNCH_KERNEL(185); break;
		case 186: LAUNCH_KERNEL(186); break;
		case 187: LAUNCH_KERNEL(187); break;
		case 188: LAUNCH_KERNEL(188); break;
		case 189: LAUNCH_KERNEL(189); break;
		case 190: LAUNCH_KERNEL(190); break;
		case 191: LAUNCH_KERNEL(191); break;
		case 192: LAUNCH_KERNEL(192); break;
		case 193: LAUNCH_KERNEL(193); break;
		case 194: LAUNCH_KERNEL(194); break;
		case 195: LAUNCH_KERNEL(195); break;
		case 196: LAUNCH_KERNEL(196); break;
		case 197: LAUNCH_KERNEL(197); break;
		case 198: LAUNCH_KERNEL(198); break;
		case 199: LAUNCH_KERNEL(199); break;
		case 200: LAUNCH_KERNEL(200); break;
		case 201: LAUNCH_KERNEL(201); break;
		case 202: LAUNCH_KERNEL(202); break;
		case 203: LAUNCH_KERNEL(203); break;
		case 204: LAUNCH_KERNEL(204); break;
		case 205: LAUNCH_KERNEL(205); break;
		case 206: LAUNCH_KERNEL(206); break;
		case 207: LAUNCH_KERNEL(207); break;
		case 208: LAUNCH_KERNEL(208); break;
		case 209: LAUNCH_KERNEL(209); break;
		case 210: LAUNCH_KERNEL(210); break;
		case 211: LAUNCH_KERNEL(211); break;
		case 212: LAUNCH_KERNEL(212); break;
		case 213: LAUNCH_KERNEL(213); break;
		case 214: LAUNCH_KERNEL(214); break;
		case 215: LAUNCH_KERNEL(215); break;
		case 216: LAUNCH_KERNEL(216); break;
		case 217: LAUNCH_KERNEL(217); break;
		case 218: LAUNCH_KERNEL(218); break;
		case 219: LAUNCH_KERNEL(219); break;
		case 220: LAUNCH_KERNEL(220); break;
		case 221: LAUNCH_KERNEL(221); break;
		case 222: LAUNCH_KERNEL(222); break;
		case 223: LAUNCH_KERNEL(223); break;
		case 224: LAUNCH_KERNEL(224); break;
		case 225: LAUNCH_KERNEL(225); break;
		case 226: LAUNCH_KERNEL(226); break;
		case 227: LAUNCH_KERNEL(227); break;
		case 228: LAUNCH_KERNEL(228); break;
		case 229: LAUNCH_KERNEL(229); break;
		case 230: LAUNCH_KERNEL(230); break;
		case 231: LAUNCH_KERNEL(231); break;
		case 232: LAUNCH_KERNEL(232); break;
		case 233: LAUNCH_KERNEL(233); break;
		case 234: LAUNCH_KERNEL(234); break;
		case 235: LAUNCH_KERNEL(235); break;
		case 236: LAUNCH_KERNEL(236); break;
		case 237: LAUNCH_KERNEL(237); break;
		case 238: LAUNCH_KERNEL(238); break;
		case 239: LAUNCH_KERNEL(239); break;
		case 240: LAUNCH_KERNEL(240); break;
		case 241: LAUNCH_KERNEL(241); break;
		case 242: LAUNCH_KERNEL(242); break;
		case 243: LAUNCH_KERNEL(243); break;
		case 244: LAUNCH_KERNEL(244); break;
		case 245: LAUNCH_KERNEL(245); break;
		case 246: LAUNCH_KERNEL(246); break;
		case 247: LAUNCH_KERNEL(247); break;
		case 248: LAUNCH_KERNEL(248); break;
		case 249: LAUNCH_KERNEL(249); break;
		case 250: LAUNCH_KERNEL(250); break;
		case 251: LAUNCH_KERNEL(251); break;
		case 252: LAUNCH_KERNEL(252); break;
		case 253: LAUNCH_KERNEL(253); break;
		case 254: LAUNCH_KERNEL(254); break;
		case 255: LAUNCH_KERNEL(255); break;
		case 256: LAUNCH_KERNEL(256); break;
		case 257: LAUNCH_KERNEL(257); break;
		case 258: LAUNCH_KERNEL(258); break;
		case 259: LAUNCH_KERNEL(259); break;
		case 260: LAUNCH_KERNEL(260); break;
		case 261: LAUNCH_KERNEL(261); break;
		case 262: LAUNCH_KERNEL(262); break;
		case 263: LAUNCH_KERNEL(263); break;
		case 264: LAUNCH_KERNEL(264); break;
		case 265: LAUNCH_KERNEL(265); break;
		case 266: LAUNCH_KERNEL(266); break;
		case 267: LAUNCH_KERNEL(267); break;
		case 268: LAUNCH_KERNEL(268); break;
		case 269: LAUNCH_KERNEL(269); break;
		case 270: LAUNCH_KERNEL(270); break;
		case 271: LAUNCH_KERNEL(271); break;
		case 272: LAUNCH_KERNEL(272); break;
		case 273: LAUNCH_KERNEL(273); break;
		case 274: LAUNCH_KERNEL(274); break;
		case 275: LAUNCH_KERNEL(275); break;
		case 276: LAUNCH_KERNEL(276); break;
		case 277: LAUNCH_KERNEL(277); break;
		case 278: LAUNCH_KERNEL(278); break;
		case 279: LAUNCH_KERNEL(279); break;
		case 280: LAUNCH_KERNEL(280); break;
		case 281: LAUNCH_KERNEL(281); break;
		case 282: LAUNCH_KERNEL(282); break;
		case 283: LAUNCH_KERNEL(283); break;
		case 284: LAUNCH_KERNEL(284); break;
		case 285: LAUNCH_KERNEL(285); break;
		case 286: LAUNCH_KERNEL(286); break;
		case 287: LAUNCH_KERNEL(287); break;
		case 288: LAUNCH_KERNEL(288); break;
		case 289: LAUNCH_KERNEL(289); break;
		case 290: LAUNCH_KERNEL(290); break;
		case 291: LAUNCH_KERNEL(291); break;
		case 292: LAUNCH_KERNEL(292); break;
		case 293: LAUNCH_KERNEL(293); break;
		case 294: LAUNCH_KERNEL(294); break;
		case 295: LAUNCH_KERNEL(295); break;
		case 296: LAUNCH_KERNEL(296); break;
		case 297: LAUNCH_KERNEL(297); break;
		case 298: LAUNCH_KERNEL(298); break;
		case 299: LAUNCH_KERNEL(299); break;
		case 300: LAUNCH_KERNEL(300); break;
		case 301: LAUNCH_KERNEL(301); break;
		case 302: LAUNCH_KERNEL(302); break;
		case 303: LAUNCH_KERNEL(303); break;
		case 304: LAUNCH_KERNEL(304); break;
		case 305: LAUNCH_KERNEL(305); break;
		case 306: LAUNCH_KERNEL(306); break;
		case 307: LAUNCH_KERNEL(307); break;
		case 308: LAUNCH_KERNEL(308); break;
		case 309: LAUNCH_KERNEL(309); break;
		case 310: LAUNCH_KERNEL(310); break;
		case 311: LAUNCH_KERNEL(311); break;
		case 312: LAUNCH_KERNEL(312); break;
		case 313: LAUNCH_KERNEL(313); break;
		case 314: LAUNCH_KERNEL(314); break;
		case 315: LAUNCH_KERNEL(315); break;
		case 316: LAUNCH_KERNEL(316); break;
		case 317: LAUNCH_KERNEL(317); break;
		case 318: LAUNCH_KERNEL(318); break;
		case 319: LAUNCH_KERNEL(319); break;
		case 320: LAUNCH_KERNEL(320); break;
		case 321: LAUNCH_KERNEL(321); break;
		case 322: LAUNCH_KERNEL(322); break;
		case 323: LAUNCH_KERNEL(323); break;
		case 324: LAUNCH_KERNEL(324); break;
		case 325: LAUNCH_KERNEL(325); break;
		case 326: LAUNCH_KERNEL(326); break;
		case 327: LAUNCH_KERNEL(327); break;
		case 328: LAUNCH_KERNEL(328); break;
		case 329: LAUNCH_KERNEL(329); break;
		case 330: LAUNCH_KERNEL(330); break;
		case 331: LAUNCH_KERNEL(331); break;
		case 332: LAUNCH_KERNEL(332); break;
		case 333: LAUNCH_KERNEL(333); break;
		case 334: LAUNCH_KERNEL(334); break;
		case 335: LAUNCH_KERNEL(335); break;
		case 336: LAUNCH_KERNEL(336); break;
		case 337: LAUNCH_KERNEL(337); break;
		case 338: LAUNCH_KERNEL(338); break;
		case 339: LAUNCH_KERNEL(339); break;
		case 340: LAUNCH_KERNEL(340); break;
		case 341: LAUNCH_KERNEL(341); break;
		case 342: LAUNCH_KERNEL(342); break;
		case 343: LAUNCH_KERNEL(343); break;
		case 344: LAUNCH_KERNEL(344); break;
		case 345: LAUNCH_KERNEL(345); break;
		case 346: LAUNCH_KERNEL(346); break;
		case 347: LAUNCH_KERNEL(347); break;
		case 348: LAUNCH_KERNEL(348); break;
		case 349: LAUNCH_KERNEL(349); break;
		case 350: LAUNCH_KERNEL(350); break;
		case 351: LAUNCH_KERNEL(351); break;
		case 352: LAUNCH_KERNEL(352); break;
		case 353: LAUNCH_KERNEL(353); break;
		case 354: LAUNCH_KERNEL(354); break;
		case 355: LAUNCH_KERNEL(355); break;
		case 356: LAUNCH_KERNEL(356); break;
		case 357: LAUNCH_KERNEL(357); break;
		case 358: LAUNCH_KERNEL(358); break;
		case 359: LAUNCH_KERNEL(359); break;
		case 360: LAUNCH_KERNEL(360); break;
		case 361: LAUNCH_KERNEL(361); break;
		case 362: LAUNCH_KERNEL(362); break;
		case 363: LAUNCH_KERNEL(363); break;
		case 364: LAUNCH_KERNEL(364); break;
		case 365: LAUNCH_KERNEL(365); break;
		case 366: LAUNCH_KERNEL(366); break;
		case 367: LAUNCH_KERNEL(367); break;
		case 368: LAUNCH_KERNEL(368); break;
		case 369: LAUNCH_KERNEL(369); break;
		case 370: LAUNCH_KERNEL(370); break;
		case 371: LAUNCH_KERNEL(371); break;
		case 372: LAUNCH_KERNEL(372); break;
		case 373: LAUNCH_KERNEL(373); break;
		case 374: LAUNCH_KERNEL(374); break;
		case 375: LAUNCH_KERNEL(375); break;
		case 376: LAUNCH_KERNEL(376); break;
		case 377: LAUNCH_KERNEL(377); break;
		case 378: LAUNCH_KERNEL(378); break;
		case 379: LAUNCH_KERNEL(379); break;
		case 380: LAUNCH_KERNEL(380); break;
		case 381: LAUNCH_KERNEL(381); break;
		case 382: LAUNCH_KERNEL(382); break;
		case 383: LAUNCH_KERNEL(383); break;
		case 384: LAUNCH_KERNEL(384); break;
		case 385: LAUNCH_KERNEL(385); break;
		case 386: LAUNCH_KERNEL(386); break;
		case 387: LAUNCH_KERNEL(387); break;
		case 388: LAUNCH_KERNEL(388); break;
		case 389: LAUNCH_KERNEL(389); break;
		case 390: LAUNCH_KERNEL(390); break;
		case 391: LAUNCH_KERNEL(391); break;
		case 392: LAUNCH_KERNEL(392); break;
		case 393: LAUNCH_KERNEL(393); break;
		case 394: LAUNCH_KERNEL(394); break;
		case 395: LAUNCH_KERNEL(395); break;
		case 396: LAUNCH_KERNEL(396); break;
		case 397: LAUNCH_KERNEL(397); break;
		case 398: LAUNCH_KERNEL(398); break;
		case 399: LAUNCH_KERNEL(399); break;
		case 400: LAUNCH_KERNEL(400); break;
		case 401: LAUNCH_KERNEL(401); break;
		case 402: LAUNCH_KERNEL(402); break;
		case 403: LAUNCH_KERNEL(403); break;
		case 404: LAUNCH_KERNEL(404); break;
		case 405: LAUNCH_KERNEL(405); break;
		case 406: LAUNCH_KERNEL(406); break;
		case 407: LAUNCH_KERNEL(407); break;
		case 408: LAUNCH_KERNEL(408); break;
		case 409: LAUNCH_KERNEL(409); break;
		case 410: LAUNCH_KERNEL(410); break;
		case 411: LAUNCH_KERNEL(411); break;
		case 412: LAUNCH_KERNEL(412); break;
		case 413: LAUNCH_KERNEL(413); break;
		case 414: LAUNCH_KERNEL(414); break;
		case 415: LAUNCH_KERNEL(415); break;
		case 416: LAUNCH_KERNEL(416); break;
		case 417: LAUNCH_KERNEL(417); break;
		case 418: LAUNCH_KERNEL(418); break;
		case 419: LAUNCH_KERNEL(419); break;
		case 420: LAUNCH_KERNEL(420); break;
		case 421: LAUNCH_KERNEL(421); break;
		case 422: LAUNCH_KERNEL(422); break;
		case 423: LAUNCH_KERNEL(423); break;
		case 424: LAUNCH_KERNEL(424); break;
		case 425: LAUNCH_KERNEL(425); break;
		case 426: LAUNCH_KERNEL(426); break;
		case 427: LAUNCH_KERNEL(427); break;
		case 428: LAUNCH_KERNEL(428); break;
		case 429: LAUNCH_KERNEL(429); break;
		case 430: LAUNCH_KERNEL(430); break;
		case 431: LAUNCH_KERNEL(431); break;
		case 432: LAUNCH_KERNEL(432); break;
		case 433: LAUNCH_KERNEL(433); break;
		case 434: LAUNCH_KERNEL(434); break;
		case 435: LAUNCH_KERNEL(435); break;
		case 436: LAUNCH_KERNEL(436); break;
		case 437: LAUNCH_KERNEL(437); break;
		case 438: LAUNCH_KERNEL(438); break;
		case 439: LAUNCH_KERNEL(439); break;
		case 440: LAUNCH_KERNEL(440); break;
		case 441: LAUNCH_KERNEL(441); break;
		case 442: LAUNCH_KERNEL(442); break;
		case 443: LAUNCH_KERNEL(443); break;
		case 444: LAUNCH_KERNEL(444); break;
		case 445: LAUNCH_KERNEL(445); break;
		case 446: LAUNCH_KERNEL(446); break;
		case 447: LAUNCH_KERNEL(447); break;
		case 448: LAUNCH_KERNEL(448); break;
		case 449: LAUNCH_KERNEL(449); break;
		case 450: LAUNCH_KERNEL(450); break;
		case 451: LAUNCH_KERNEL(451); break;
		case 452: LAUNCH_KERNEL(452); break;
		case 453: LAUNCH_KERNEL(453); break;
		case 454: LAUNCH_KERNEL(454); break;
		case 455: LAUNCH_KERNEL(455); break;
		case 456: LAUNCH_KERNEL(456); break;
		case 457: LAUNCH_KERNEL(457); break;
		case 458: LAUNCH_KERNEL(458); break;
		case 459: LAUNCH_KERNEL(459); break;
		case 460: LAUNCH_KERNEL(460); break;
		case 461: LAUNCH_KERNEL(461); break;
		case 462: LAUNCH_KERNEL(462); break;
		case 463: LAUNCH_KERNEL(463); break;
		case 464: LAUNCH_KERNEL(464); break;
		case 465: LAUNCH_KERNEL(465); break;
		case 466: LAUNCH_KERNEL(466); break;
		case 467: LAUNCH_KERNEL(467); break;
		case 468: LAUNCH_KERNEL(468); break;
		case 469: LAUNCH_KERNEL(469); break;
		case 470: LAUNCH_KERNEL(470); break;
		case 471: LAUNCH_KERNEL(471); break;
		case 472: LAUNCH_KERNEL(472); break;
		case 473: LAUNCH_KERNEL(473); break;
		case 474: LAUNCH_KERNEL(474); break;
		case 475: LAUNCH_KERNEL(475); break;
		case 476: LAUNCH_KERNEL(476); break;
		case 477: LAUNCH_KERNEL(477); break;
		case 478: LAUNCH_KERNEL(478); break;
		case 479: LAUNCH_KERNEL(479); break;
		case 480: LAUNCH_KERNEL(480); break;
		case 481: LAUNCH_KERNEL(481); break;
		case 482: LAUNCH_KERNEL(482); break;
		case 483: LAUNCH_KERNEL(483); break;
		case 484: LAUNCH_KERNEL(484); break;
		case 485: LAUNCH_KERNEL(485); break;
		case 486: LAUNCH_KERNEL(486); break;
		case 487: LAUNCH_KERNEL(487); break;
		case 488: LAUNCH_KERNEL(488); break;
		case 489: LAUNCH_KERNEL(489); break;
		case 490: LAUNCH_KERNEL(490); break;
		case 491: LAUNCH_KERNEL(491); break;
		case 492: LAUNCH_KERNEL(492); break;
		case 493: LAUNCH_KERNEL(493); break;
		case 494: LAUNCH_KERNEL(494); break;
		case 495: LAUNCH_KERNEL(495); break;
		case 496: LAUNCH_KERNEL(496); break;
		case 497: LAUNCH_KERNEL(497); break;
		case 498: LAUNCH_KERNEL(498); break;
		case 499: LAUNCH_KERNEL(499); break;
		case 500: LAUNCH_KERNEL(500); break;
		case 501: LAUNCH_KERNEL(501); break;
		case 502: LAUNCH_KERNEL(502); break;
		case 503: LAUNCH_KERNEL(503); break;
		case 504: LAUNCH_KERNEL(504); break;
		case 505: LAUNCH_KERNEL(505); break;
		case 506: LAUNCH_KERNEL(506); break;
		case 507: LAUNCH_KERNEL(507); break;
		case 508: LAUNCH_KERNEL(508); break;
		case 509: LAUNCH_KERNEL(509); break;
		case 510: LAUNCH_KERNEL(510); break;
		case 511: LAUNCH_KERNEL(511); break;
		default: ASSERT(FALSE);
	}
}
