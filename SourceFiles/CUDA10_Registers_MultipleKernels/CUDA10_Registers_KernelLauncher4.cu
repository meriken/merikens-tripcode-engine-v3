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

#define SALT 1024
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1025
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1026
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1027
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1028
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1029
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1030
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1031
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1032
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1033
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1034
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1035
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1036
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1037
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1038
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1039
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1040
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1041
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1042
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1043
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1044
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1045
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1046
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1047
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1048
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1049
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1050
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1051
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1052
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1053
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1054
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1055
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1056
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1057
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1058
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1059
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1060
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1061
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1062
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1063
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1064
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1065
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1066
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1067
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1068
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1069
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1070
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1071
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1072
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1073
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1074
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1075
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1076
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1077
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1078
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1079
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1080
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1081
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1082
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1083
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1084
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1085
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1086
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1087
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1088
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1089
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1090
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1091
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1092
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1093
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1094
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1095
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1096
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1097
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1098
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1099
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1100
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1101
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1102
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1103
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1104
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1105
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1106
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1107
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1108
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1109
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1110
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1111
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1112
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1113
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1114
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1115
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1116
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1117
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1118
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1119
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1120
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1121
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1122
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1123
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1124
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1125
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1126
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1127
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1128
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1129
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1130
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1131
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1132
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1133
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1134
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1135
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1136
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1137
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1138
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1139
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1140
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1141
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1142
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1143
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1144
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1145
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1146
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1147
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1148
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1149
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1150
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1151
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1152
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1153
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1154
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1155
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1156
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1157
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1158
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1159
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1160
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1161
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1162
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1163
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1164
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1165
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1166
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1167
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1168
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1169
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1170
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1171
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1172
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1173
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1174
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1175
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1176
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1177
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1178
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1179
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1180
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1181
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1182
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1183
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1184
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1185
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1186
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1187
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1188
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1189
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1190
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1191
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1192
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1193
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1194
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1195
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1196
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1197
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1198
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1199
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1200
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1201
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1202
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1203
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1204
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1205
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1206
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1207
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1208
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1209
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1210
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1211
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1212
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1213
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1214
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1215
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1216
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1217
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1218
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1219
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1220
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1221
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1222
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1223
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1224
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1225
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1226
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1227
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1228
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1229
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1230
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1231
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1232
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1233
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1234
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1235
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1236
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1237
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1238
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1239
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1240
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1241
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1242
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1243
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1244
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1245
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1246
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1247
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1248
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1249
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1250
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1251
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1252
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1253
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1254
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1255
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1256
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1257
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1258
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1259
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1260
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1261
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1262
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1263
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1264
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1265
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1266
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1267
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1268
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1269
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1270
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1271
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1272
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1273
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1274
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1275
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1276
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1277
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1278
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1279
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher4()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel4(
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
	case 1024: LAUNCH_KERNEL(1024); break;
	case 1025: LAUNCH_KERNEL(1025); break;
	case 1026: LAUNCH_KERNEL(1026); break;
	case 1027: LAUNCH_KERNEL(1027); break;
	case 1028: LAUNCH_KERNEL(1028); break;
	case 1029: LAUNCH_KERNEL(1029); break;
	case 1030: LAUNCH_KERNEL(1030); break;
	case 1031: LAUNCH_KERNEL(1031); break;
	case 1032: LAUNCH_KERNEL(1032); break;
	case 1033: LAUNCH_KERNEL(1033); break;
	case 1034: LAUNCH_KERNEL(1034); break;
	case 1035: LAUNCH_KERNEL(1035); break;
	case 1036: LAUNCH_KERNEL(1036); break;
	case 1037: LAUNCH_KERNEL(1037); break;
	case 1038: LAUNCH_KERNEL(1038); break;
	case 1039: LAUNCH_KERNEL(1039); break;
	case 1040: LAUNCH_KERNEL(1040); break;
	case 1041: LAUNCH_KERNEL(1041); break;
	case 1042: LAUNCH_KERNEL(1042); break;
	case 1043: LAUNCH_KERNEL(1043); break;
	case 1044: LAUNCH_KERNEL(1044); break;
	case 1045: LAUNCH_KERNEL(1045); break;
	case 1046: LAUNCH_KERNEL(1046); break;
	case 1047: LAUNCH_KERNEL(1047); break;
	case 1048: LAUNCH_KERNEL(1048); break;
	case 1049: LAUNCH_KERNEL(1049); break;
	case 1050: LAUNCH_KERNEL(1050); break;
	case 1051: LAUNCH_KERNEL(1051); break;
	case 1052: LAUNCH_KERNEL(1052); break;
	case 1053: LAUNCH_KERNEL(1053); break;
	case 1054: LAUNCH_KERNEL(1054); break;
	case 1055: LAUNCH_KERNEL(1055); break;
	case 1056: LAUNCH_KERNEL(1056); break;
	case 1057: LAUNCH_KERNEL(1057); break;
	case 1058: LAUNCH_KERNEL(1058); break;
	case 1059: LAUNCH_KERNEL(1059); break;
	case 1060: LAUNCH_KERNEL(1060); break;
	case 1061: LAUNCH_KERNEL(1061); break;
	case 1062: LAUNCH_KERNEL(1062); break;
	case 1063: LAUNCH_KERNEL(1063); break;
	case 1064: LAUNCH_KERNEL(1064); break;
	case 1065: LAUNCH_KERNEL(1065); break;
	case 1066: LAUNCH_KERNEL(1066); break;
	case 1067: LAUNCH_KERNEL(1067); break;
	case 1068: LAUNCH_KERNEL(1068); break;
	case 1069: LAUNCH_KERNEL(1069); break;
	case 1070: LAUNCH_KERNEL(1070); break;
	case 1071: LAUNCH_KERNEL(1071); break;
	case 1072: LAUNCH_KERNEL(1072); break;
	case 1073: LAUNCH_KERNEL(1073); break;
	case 1074: LAUNCH_KERNEL(1074); break;
	case 1075: LAUNCH_KERNEL(1075); break;
	case 1076: LAUNCH_KERNEL(1076); break;
	case 1077: LAUNCH_KERNEL(1077); break;
	case 1078: LAUNCH_KERNEL(1078); break;
	case 1079: LAUNCH_KERNEL(1079); break;
	case 1080: LAUNCH_KERNEL(1080); break;
	case 1081: LAUNCH_KERNEL(1081); break;
	case 1082: LAUNCH_KERNEL(1082); break;
	case 1083: LAUNCH_KERNEL(1083); break;
	case 1084: LAUNCH_KERNEL(1084); break;
	case 1085: LAUNCH_KERNEL(1085); break;
	case 1086: LAUNCH_KERNEL(1086); break;
	case 1087: LAUNCH_KERNEL(1087); break;
	case 1088: LAUNCH_KERNEL(1088); break;
	case 1089: LAUNCH_KERNEL(1089); break;
	case 1090: LAUNCH_KERNEL(1090); break;
	case 1091: LAUNCH_KERNEL(1091); break;
	case 1092: LAUNCH_KERNEL(1092); break;
	case 1093: LAUNCH_KERNEL(1093); break;
	case 1094: LAUNCH_KERNEL(1094); break;
	case 1095: LAUNCH_KERNEL(1095); break;
	case 1096: LAUNCH_KERNEL(1096); break;
	case 1097: LAUNCH_KERNEL(1097); break;
	case 1098: LAUNCH_KERNEL(1098); break;
	case 1099: LAUNCH_KERNEL(1099); break;
	case 1100: LAUNCH_KERNEL(1100); break;
	case 1101: LAUNCH_KERNEL(1101); break;
	case 1102: LAUNCH_KERNEL(1102); break;
	case 1103: LAUNCH_KERNEL(1103); break;
	case 1104: LAUNCH_KERNEL(1104); break;
	case 1105: LAUNCH_KERNEL(1105); break;
	case 1106: LAUNCH_KERNEL(1106); break;
	case 1107: LAUNCH_KERNEL(1107); break;
	case 1108: LAUNCH_KERNEL(1108); break;
	case 1109: LAUNCH_KERNEL(1109); break;
	case 1110: LAUNCH_KERNEL(1110); break;
	case 1111: LAUNCH_KERNEL(1111); break;
	case 1112: LAUNCH_KERNEL(1112); break;
	case 1113: LAUNCH_KERNEL(1113); break;
	case 1114: LAUNCH_KERNEL(1114); break;
	case 1115: LAUNCH_KERNEL(1115); break;
	case 1116: LAUNCH_KERNEL(1116); break;
	case 1117: LAUNCH_KERNEL(1117); break;
	case 1118: LAUNCH_KERNEL(1118); break;
	case 1119: LAUNCH_KERNEL(1119); break;
	case 1120: LAUNCH_KERNEL(1120); break;
	case 1121: LAUNCH_KERNEL(1121); break;
	case 1122: LAUNCH_KERNEL(1122); break;
	case 1123: LAUNCH_KERNEL(1123); break;
	case 1124: LAUNCH_KERNEL(1124); break;
	case 1125: LAUNCH_KERNEL(1125); break;
	case 1126: LAUNCH_KERNEL(1126); break;
	case 1127: LAUNCH_KERNEL(1127); break;
	case 1128: LAUNCH_KERNEL(1128); break;
	case 1129: LAUNCH_KERNEL(1129); break;
	case 1130: LAUNCH_KERNEL(1130); break;
	case 1131: LAUNCH_KERNEL(1131); break;
	case 1132: LAUNCH_KERNEL(1132); break;
	case 1133: LAUNCH_KERNEL(1133); break;
	case 1134: LAUNCH_KERNEL(1134); break;
	case 1135: LAUNCH_KERNEL(1135); break;
	case 1136: LAUNCH_KERNEL(1136); break;
	case 1137: LAUNCH_KERNEL(1137); break;
	case 1138: LAUNCH_KERNEL(1138); break;
	case 1139: LAUNCH_KERNEL(1139); break;
	case 1140: LAUNCH_KERNEL(1140); break;
	case 1141: LAUNCH_KERNEL(1141); break;
	case 1142: LAUNCH_KERNEL(1142); break;
	case 1143: LAUNCH_KERNEL(1143); break;
	case 1144: LAUNCH_KERNEL(1144); break;
	case 1145: LAUNCH_KERNEL(1145); break;
	case 1146: LAUNCH_KERNEL(1146); break;
	case 1147: LAUNCH_KERNEL(1147); break;
	case 1148: LAUNCH_KERNEL(1148); break;
	case 1149: LAUNCH_KERNEL(1149); break;
	case 1150: LAUNCH_KERNEL(1150); break;
	case 1151: LAUNCH_KERNEL(1151); break;
	case 1152: LAUNCH_KERNEL(1152); break;
	case 1153: LAUNCH_KERNEL(1153); break;
	case 1154: LAUNCH_KERNEL(1154); break;
	case 1155: LAUNCH_KERNEL(1155); break;
	case 1156: LAUNCH_KERNEL(1156); break;
	case 1157: LAUNCH_KERNEL(1157); break;
	case 1158: LAUNCH_KERNEL(1158); break;
	case 1159: LAUNCH_KERNEL(1159); break;
	case 1160: LAUNCH_KERNEL(1160); break;
	case 1161: LAUNCH_KERNEL(1161); break;
	case 1162: LAUNCH_KERNEL(1162); break;
	case 1163: LAUNCH_KERNEL(1163); break;
	case 1164: LAUNCH_KERNEL(1164); break;
	case 1165: LAUNCH_KERNEL(1165); break;
	case 1166: LAUNCH_KERNEL(1166); break;
	case 1167: LAUNCH_KERNEL(1167); break;
	case 1168: LAUNCH_KERNEL(1168); break;
	case 1169: LAUNCH_KERNEL(1169); break;
	case 1170: LAUNCH_KERNEL(1170); break;
	case 1171: LAUNCH_KERNEL(1171); break;
	case 1172: LAUNCH_KERNEL(1172); break;
	case 1173: LAUNCH_KERNEL(1173); break;
	case 1174: LAUNCH_KERNEL(1174); break;
	case 1175: LAUNCH_KERNEL(1175); break;
	case 1176: LAUNCH_KERNEL(1176); break;
	case 1177: LAUNCH_KERNEL(1177); break;
	case 1178: LAUNCH_KERNEL(1178); break;
	case 1179: LAUNCH_KERNEL(1179); break;
	case 1180: LAUNCH_KERNEL(1180); break;
	case 1181: LAUNCH_KERNEL(1181); break;
	case 1182: LAUNCH_KERNEL(1182); break;
	case 1183: LAUNCH_KERNEL(1183); break;
	case 1184: LAUNCH_KERNEL(1184); break;
	case 1185: LAUNCH_KERNEL(1185); break;
	case 1186: LAUNCH_KERNEL(1186); break;
	case 1187: LAUNCH_KERNEL(1187); break;
	case 1188: LAUNCH_KERNEL(1188); break;
	case 1189: LAUNCH_KERNEL(1189); break;
	case 1190: LAUNCH_KERNEL(1190); break;
	case 1191: LAUNCH_KERNEL(1191); break;
	case 1192: LAUNCH_KERNEL(1192); break;
	case 1193: LAUNCH_KERNEL(1193); break;
	case 1194: LAUNCH_KERNEL(1194); break;
	case 1195: LAUNCH_KERNEL(1195); break;
	case 1196: LAUNCH_KERNEL(1196); break;
	case 1197: LAUNCH_KERNEL(1197); break;
	case 1198: LAUNCH_KERNEL(1198); break;
	case 1199: LAUNCH_KERNEL(1199); break;
	case 1200: LAUNCH_KERNEL(1200); break;
	case 1201: LAUNCH_KERNEL(1201); break;
	case 1202: LAUNCH_KERNEL(1202); break;
	case 1203: LAUNCH_KERNEL(1203); break;
	case 1204: LAUNCH_KERNEL(1204); break;
	case 1205: LAUNCH_KERNEL(1205); break;
	case 1206: LAUNCH_KERNEL(1206); break;
	case 1207: LAUNCH_KERNEL(1207); break;
	case 1208: LAUNCH_KERNEL(1208); break;
	case 1209: LAUNCH_KERNEL(1209); break;
	case 1210: LAUNCH_KERNEL(1210); break;
	case 1211: LAUNCH_KERNEL(1211); break;
	case 1212: LAUNCH_KERNEL(1212); break;
	case 1213: LAUNCH_KERNEL(1213); break;
	case 1214: LAUNCH_KERNEL(1214); break;
	case 1215: LAUNCH_KERNEL(1215); break;
	case 1216: LAUNCH_KERNEL(1216); break;
	case 1217: LAUNCH_KERNEL(1217); break;
	case 1218: LAUNCH_KERNEL(1218); break;
	case 1219: LAUNCH_KERNEL(1219); break;
	case 1220: LAUNCH_KERNEL(1220); break;
	case 1221: LAUNCH_KERNEL(1221); break;
	case 1222: LAUNCH_KERNEL(1222); break;
	case 1223: LAUNCH_KERNEL(1223); break;
	case 1224: LAUNCH_KERNEL(1224); break;
	case 1225: LAUNCH_KERNEL(1225); break;
	case 1226: LAUNCH_KERNEL(1226); break;
	case 1227: LAUNCH_KERNEL(1227); break;
	case 1228: LAUNCH_KERNEL(1228); break;
	case 1229: LAUNCH_KERNEL(1229); break;
	case 1230: LAUNCH_KERNEL(1230); break;
	case 1231: LAUNCH_KERNEL(1231); break;
	case 1232: LAUNCH_KERNEL(1232); break;
	case 1233: LAUNCH_KERNEL(1233); break;
	case 1234: LAUNCH_KERNEL(1234); break;
	case 1235: LAUNCH_KERNEL(1235); break;
	case 1236: LAUNCH_KERNEL(1236); break;
	case 1237: LAUNCH_KERNEL(1237); break;
	case 1238: LAUNCH_KERNEL(1238); break;
	case 1239: LAUNCH_KERNEL(1239); break;
	case 1240: LAUNCH_KERNEL(1240); break;
	case 1241: LAUNCH_KERNEL(1241); break;
	case 1242: LAUNCH_KERNEL(1242); break;
	case 1243: LAUNCH_KERNEL(1243); break;
	case 1244: LAUNCH_KERNEL(1244); break;
	case 1245: LAUNCH_KERNEL(1245); break;
	case 1246: LAUNCH_KERNEL(1246); break;
	case 1247: LAUNCH_KERNEL(1247); break;
	case 1248: LAUNCH_KERNEL(1248); break;
	case 1249: LAUNCH_KERNEL(1249); break;
	case 1250: LAUNCH_KERNEL(1250); break;
	case 1251: LAUNCH_KERNEL(1251); break;
	case 1252: LAUNCH_KERNEL(1252); break;
	case 1253: LAUNCH_KERNEL(1253); break;
	case 1254: LAUNCH_KERNEL(1254); break;
	case 1255: LAUNCH_KERNEL(1255); break;
	case 1256: LAUNCH_KERNEL(1256); break;
	case 1257: LAUNCH_KERNEL(1257); break;
	case 1258: LAUNCH_KERNEL(1258); break;
	case 1259: LAUNCH_KERNEL(1259); break;
	case 1260: LAUNCH_KERNEL(1260); break;
	case 1261: LAUNCH_KERNEL(1261); break;
	case 1262: LAUNCH_KERNEL(1262); break;
	case 1263: LAUNCH_KERNEL(1263); break;
	case 1264: LAUNCH_KERNEL(1264); break;
	case 1265: LAUNCH_KERNEL(1265); break;
	case 1266: LAUNCH_KERNEL(1266); break;
	case 1267: LAUNCH_KERNEL(1267); break;
	case 1268: LAUNCH_KERNEL(1268); break;
	case 1269: LAUNCH_KERNEL(1269); break;
	case 1270: LAUNCH_KERNEL(1270); break;
	case 1271: LAUNCH_KERNEL(1271); break;
	case 1272: LAUNCH_KERNEL(1272); break;
	case 1273: LAUNCH_KERNEL(1273); break;
	case 1274: LAUNCH_KERNEL(1274); break;
	case 1275: LAUNCH_KERNEL(1275); break;
	case 1276: LAUNCH_KERNEL(1276); break;
	case 1277: LAUNCH_KERNEL(1277); break;
	case 1278: LAUNCH_KERNEL(1278); break;
	case 1279: LAUNCH_KERNEL(1279); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
