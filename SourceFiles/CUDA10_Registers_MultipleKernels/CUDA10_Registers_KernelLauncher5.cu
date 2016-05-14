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

#define SALT 1280
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1281
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1282
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1283
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1284
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1285
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1286
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1287
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1288
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1289
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1290
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1291
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1292
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1293
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1294
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1295
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1296
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1297
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1298
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1299
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1300
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1301
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1302
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1303
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1304
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1305
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1306
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1307
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1308
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1309
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1310
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1311
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1312
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1313
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1314
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1315
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1316
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1317
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1318
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1319
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1320
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1321
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1322
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1323
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1324
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1325
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1326
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1327
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1328
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1329
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1330
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1331
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1332
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1333
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1334
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1335
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1336
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1337
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1338
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1339
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1340
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1341
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1342
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1343
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1344
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1345
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1346
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1347
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1348
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1349
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1350
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1351
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1352
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1353
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1354
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1355
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1356
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1357
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1358
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1359
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1360
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1361
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1362
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1363
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1364
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1365
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1366
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1367
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1368
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1369
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1370
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1371
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1372
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1373
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1374
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1375
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1376
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1377
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1378
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1379
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1380
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1381
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1382
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1383
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1384
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1385
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1386
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1387
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1388
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1389
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1390
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1391
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1392
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1393
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1394
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1395
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1396
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1397
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1398
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1399
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1400
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1401
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1402
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1403
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1404
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1405
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1406
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1407
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1408
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1409
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1410
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1411
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1412
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1413
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1414
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1415
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1416
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1417
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1418
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1419
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1420
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1421
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1422
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1423
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1424
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1425
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1426
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1427
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1428
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1429
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1430
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1431
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1432
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1433
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1434
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1435
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1436
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1437
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1438
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1439
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1440
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1441
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1442
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1443
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1444
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1445
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1446
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1447
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1448
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1449
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1450
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1451
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1452
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1453
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1454
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1455
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1456
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1457
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1458
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1459
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1460
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1461
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1462
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1463
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1464
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1465
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1466
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1467
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1468
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1469
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1470
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1471
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1472
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1473
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1474
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1475
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1476
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1477
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1478
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1479
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1480
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1481
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1482
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1483
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1484
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1485
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1486
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1487
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1488
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1489
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1490
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1491
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1492
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1493
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1494
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1495
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1496
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1497
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1498
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1499
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1500
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1501
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1502
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1503
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1504
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1505
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1506
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1507
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1508
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1509
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1510
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1511
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1512
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1513
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1514
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1515
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1516
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1517
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1518
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1519
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1520
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1521
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1522
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1523
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1524
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1525
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1526
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1527
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1528
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1529
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1530
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1531
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1532
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1533
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1534
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1535
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher5()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel5(
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
	case 1280: LAUNCH_KERNEL(1280); break;
	case 1281: LAUNCH_KERNEL(1281); break;
	case 1282: LAUNCH_KERNEL(1282); break;
	case 1283: LAUNCH_KERNEL(1283); break;
	case 1284: LAUNCH_KERNEL(1284); break;
	case 1285: LAUNCH_KERNEL(1285); break;
	case 1286: LAUNCH_KERNEL(1286); break;
	case 1287: LAUNCH_KERNEL(1287); break;
	case 1288: LAUNCH_KERNEL(1288); break;
	case 1289: LAUNCH_KERNEL(1289); break;
	case 1290: LAUNCH_KERNEL(1290); break;
	case 1291: LAUNCH_KERNEL(1291); break;
	case 1292: LAUNCH_KERNEL(1292); break;
	case 1293: LAUNCH_KERNEL(1293); break;
	case 1294: LAUNCH_KERNEL(1294); break;
	case 1295: LAUNCH_KERNEL(1295); break;
	case 1296: LAUNCH_KERNEL(1296); break;
	case 1297: LAUNCH_KERNEL(1297); break;
	case 1298: LAUNCH_KERNEL(1298); break;
	case 1299: LAUNCH_KERNEL(1299); break;
	case 1300: LAUNCH_KERNEL(1300); break;
	case 1301: LAUNCH_KERNEL(1301); break;
	case 1302: LAUNCH_KERNEL(1302); break;
	case 1303: LAUNCH_KERNEL(1303); break;
	case 1304: LAUNCH_KERNEL(1304); break;
	case 1305: LAUNCH_KERNEL(1305); break;
	case 1306: LAUNCH_KERNEL(1306); break;
	case 1307: LAUNCH_KERNEL(1307); break;
	case 1308: LAUNCH_KERNEL(1308); break;
	case 1309: LAUNCH_KERNEL(1309); break;
	case 1310: LAUNCH_KERNEL(1310); break;
	case 1311: LAUNCH_KERNEL(1311); break;
	case 1312: LAUNCH_KERNEL(1312); break;
	case 1313: LAUNCH_KERNEL(1313); break;
	case 1314: LAUNCH_KERNEL(1314); break;
	case 1315: LAUNCH_KERNEL(1315); break;
	case 1316: LAUNCH_KERNEL(1316); break;
	case 1317: LAUNCH_KERNEL(1317); break;
	case 1318: LAUNCH_KERNEL(1318); break;
	case 1319: LAUNCH_KERNEL(1319); break;
	case 1320: LAUNCH_KERNEL(1320); break;
	case 1321: LAUNCH_KERNEL(1321); break;
	case 1322: LAUNCH_KERNEL(1322); break;
	case 1323: LAUNCH_KERNEL(1323); break;
	case 1324: LAUNCH_KERNEL(1324); break;
	case 1325: LAUNCH_KERNEL(1325); break;
	case 1326: LAUNCH_KERNEL(1326); break;
	case 1327: LAUNCH_KERNEL(1327); break;
	case 1328: LAUNCH_KERNEL(1328); break;
	case 1329: LAUNCH_KERNEL(1329); break;
	case 1330: LAUNCH_KERNEL(1330); break;
	case 1331: LAUNCH_KERNEL(1331); break;
	case 1332: LAUNCH_KERNEL(1332); break;
	case 1333: LAUNCH_KERNEL(1333); break;
	case 1334: LAUNCH_KERNEL(1334); break;
	case 1335: LAUNCH_KERNEL(1335); break;
	case 1336: LAUNCH_KERNEL(1336); break;
	case 1337: LAUNCH_KERNEL(1337); break;
	case 1338: LAUNCH_KERNEL(1338); break;
	case 1339: LAUNCH_KERNEL(1339); break;
	case 1340: LAUNCH_KERNEL(1340); break;
	case 1341: LAUNCH_KERNEL(1341); break;
	case 1342: LAUNCH_KERNEL(1342); break;
	case 1343: LAUNCH_KERNEL(1343); break;
	case 1344: LAUNCH_KERNEL(1344); break;
	case 1345: LAUNCH_KERNEL(1345); break;
	case 1346: LAUNCH_KERNEL(1346); break;
	case 1347: LAUNCH_KERNEL(1347); break;
	case 1348: LAUNCH_KERNEL(1348); break;
	case 1349: LAUNCH_KERNEL(1349); break;
	case 1350: LAUNCH_KERNEL(1350); break;
	case 1351: LAUNCH_KERNEL(1351); break;
	case 1352: LAUNCH_KERNEL(1352); break;
	case 1353: LAUNCH_KERNEL(1353); break;
	case 1354: LAUNCH_KERNEL(1354); break;
	case 1355: LAUNCH_KERNEL(1355); break;
	case 1356: LAUNCH_KERNEL(1356); break;
	case 1357: LAUNCH_KERNEL(1357); break;
	case 1358: LAUNCH_KERNEL(1358); break;
	case 1359: LAUNCH_KERNEL(1359); break;
	case 1360: LAUNCH_KERNEL(1360); break;
	case 1361: LAUNCH_KERNEL(1361); break;
	case 1362: LAUNCH_KERNEL(1362); break;
	case 1363: LAUNCH_KERNEL(1363); break;
	case 1364: LAUNCH_KERNEL(1364); break;
	case 1365: LAUNCH_KERNEL(1365); break;
	case 1366: LAUNCH_KERNEL(1366); break;
	case 1367: LAUNCH_KERNEL(1367); break;
	case 1368: LAUNCH_KERNEL(1368); break;
	case 1369: LAUNCH_KERNEL(1369); break;
	case 1370: LAUNCH_KERNEL(1370); break;
	case 1371: LAUNCH_KERNEL(1371); break;
	case 1372: LAUNCH_KERNEL(1372); break;
	case 1373: LAUNCH_KERNEL(1373); break;
	case 1374: LAUNCH_KERNEL(1374); break;
	case 1375: LAUNCH_KERNEL(1375); break;
	case 1376: LAUNCH_KERNEL(1376); break;
	case 1377: LAUNCH_KERNEL(1377); break;
	case 1378: LAUNCH_KERNEL(1378); break;
	case 1379: LAUNCH_KERNEL(1379); break;
	case 1380: LAUNCH_KERNEL(1380); break;
	case 1381: LAUNCH_KERNEL(1381); break;
	case 1382: LAUNCH_KERNEL(1382); break;
	case 1383: LAUNCH_KERNEL(1383); break;
	case 1384: LAUNCH_KERNEL(1384); break;
	case 1385: LAUNCH_KERNEL(1385); break;
	case 1386: LAUNCH_KERNEL(1386); break;
	case 1387: LAUNCH_KERNEL(1387); break;
	case 1388: LAUNCH_KERNEL(1388); break;
	case 1389: LAUNCH_KERNEL(1389); break;
	case 1390: LAUNCH_KERNEL(1390); break;
	case 1391: LAUNCH_KERNEL(1391); break;
	case 1392: LAUNCH_KERNEL(1392); break;
	case 1393: LAUNCH_KERNEL(1393); break;
	case 1394: LAUNCH_KERNEL(1394); break;
	case 1395: LAUNCH_KERNEL(1395); break;
	case 1396: LAUNCH_KERNEL(1396); break;
	case 1397: LAUNCH_KERNEL(1397); break;
	case 1398: LAUNCH_KERNEL(1398); break;
	case 1399: LAUNCH_KERNEL(1399); break;
	case 1400: LAUNCH_KERNEL(1400); break;
	case 1401: LAUNCH_KERNEL(1401); break;
	case 1402: LAUNCH_KERNEL(1402); break;
	case 1403: LAUNCH_KERNEL(1403); break;
	case 1404: LAUNCH_KERNEL(1404); break;
	case 1405: LAUNCH_KERNEL(1405); break;
	case 1406: LAUNCH_KERNEL(1406); break;
	case 1407: LAUNCH_KERNEL(1407); break;
	case 1408: LAUNCH_KERNEL(1408); break;
	case 1409: LAUNCH_KERNEL(1409); break;
	case 1410: LAUNCH_KERNEL(1410); break;
	case 1411: LAUNCH_KERNEL(1411); break;
	case 1412: LAUNCH_KERNEL(1412); break;
	case 1413: LAUNCH_KERNEL(1413); break;
	case 1414: LAUNCH_KERNEL(1414); break;
	case 1415: LAUNCH_KERNEL(1415); break;
	case 1416: LAUNCH_KERNEL(1416); break;
	case 1417: LAUNCH_KERNEL(1417); break;
	case 1418: LAUNCH_KERNEL(1418); break;
	case 1419: LAUNCH_KERNEL(1419); break;
	case 1420: LAUNCH_KERNEL(1420); break;
	case 1421: LAUNCH_KERNEL(1421); break;
	case 1422: LAUNCH_KERNEL(1422); break;
	case 1423: LAUNCH_KERNEL(1423); break;
	case 1424: LAUNCH_KERNEL(1424); break;
	case 1425: LAUNCH_KERNEL(1425); break;
	case 1426: LAUNCH_KERNEL(1426); break;
	case 1427: LAUNCH_KERNEL(1427); break;
	case 1428: LAUNCH_KERNEL(1428); break;
	case 1429: LAUNCH_KERNEL(1429); break;
	case 1430: LAUNCH_KERNEL(1430); break;
	case 1431: LAUNCH_KERNEL(1431); break;
	case 1432: LAUNCH_KERNEL(1432); break;
	case 1433: LAUNCH_KERNEL(1433); break;
	case 1434: LAUNCH_KERNEL(1434); break;
	case 1435: LAUNCH_KERNEL(1435); break;
	case 1436: LAUNCH_KERNEL(1436); break;
	case 1437: LAUNCH_KERNEL(1437); break;
	case 1438: LAUNCH_KERNEL(1438); break;
	case 1439: LAUNCH_KERNEL(1439); break;
	case 1440: LAUNCH_KERNEL(1440); break;
	case 1441: LAUNCH_KERNEL(1441); break;
	case 1442: LAUNCH_KERNEL(1442); break;
	case 1443: LAUNCH_KERNEL(1443); break;
	case 1444: LAUNCH_KERNEL(1444); break;
	case 1445: LAUNCH_KERNEL(1445); break;
	case 1446: LAUNCH_KERNEL(1446); break;
	case 1447: LAUNCH_KERNEL(1447); break;
	case 1448: LAUNCH_KERNEL(1448); break;
	case 1449: LAUNCH_KERNEL(1449); break;
	case 1450: LAUNCH_KERNEL(1450); break;
	case 1451: LAUNCH_KERNEL(1451); break;
	case 1452: LAUNCH_KERNEL(1452); break;
	case 1453: LAUNCH_KERNEL(1453); break;
	case 1454: LAUNCH_KERNEL(1454); break;
	case 1455: LAUNCH_KERNEL(1455); break;
	case 1456: LAUNCH_KERNEL(1456); break;
	case 1457: LAUNCH_KERNEL(1457); break;
	case 1458: LAUNCH_KERNEL(1458); break;
	case 1459: LAUNCH_KERNEL(1459); break;
	case 1460: LAUNCH_KERNEL(1460); break;
	case 1461: LAUNCH_KERNEL(1461); break;
	case 1462: LAUNCH_KERNEL(1462); break;
	case 1463: LAUNCH_KERNEL(1463); break;
	case 1464: LAUNCH_KERNEL(1464); break;
	case 1465: LAUNCH_KERNEL(1465); break;
	case 1466: LAUNCH_KERNEL(1466); break;
	case 1467: LAUNCH_KERNEL(1467); break;
	case 1468: LAUNCH_KERNEL(1468); break;
	case 1469: LAUNCH_KERNEL(1469); break;
	case 1470: LAUNCH_KERNEL(1470); break;
	case 1471: LAUNCH_KERNEL(1471); break;
	case 1472: LAUNCH_KERNEL(1472); break;
	case 1473: LAUNCH_KERNEL(1473); break;
	case 1474: LAUNCH_KERNEL(1474); break;
	case 1475: LAUNCH_KERNEL(1475); break;
	case 1476: LAUNCH_KERNEL(1476); break;
	case 1477: LAUNCH_KERNEL(1477); break;
	case 1478: LAUNCH_KERNEL(1478); break;
	case 1479: LAUNCH_KERNEL(1479); break;
	case 1480: LAUNCH_KERNEL(1480); break;
	case 1481: LAUNCH_KERNEL(1481); break;
	case 1482: LAUNCH_KERNEL(1482); break;
	case 1483: LAUNCH_KERNEL(1483); break;
	case 1484: LAUNCH_KERNEL(1484); break;
	case 1485: LAUNCH_KERNEL(1485); break;
	case 1486: LAUNCH_KERNEL(1486); break;
	case 1487: LAUNCH_KERNEL(1487); break;
	case 1488: LAUNCH_KERNEL(1488); break;
	case 1489: LAUNCH_KERNEL(1489); break;
	case 1490: LAUNCH_KERNEL(1490); break;
	case 1491: LAUNCH_KERNEL(1491); break;
	case 1492: LAUNCH_KERNEL(1492); break;
	case 1493: LAUNCH_KERNEL(1493); break;
	case 1494: LAUNCH_KERNEL(1494); break;
	case 1495: LAUNCH_KERNEL(1495); break;
	case 1496: LAUNCH_KERNEL(1496); break;
	case 1497: LAUNCH_KERNEL(1497); break;
	case 1498: LAUNCH_KERNEL(1498); break;
	case 1499: LAUNCH_KERNEL(1499); break;
	case 1500: LAUNCH_KERNEL(1500); break;
	case 1501: LAUNCH_KERNEL(1501); break;
	case 1502: LAUNCH_KERNEL(1502); break;
	case 1503: LAUNCH_KERNEL(1503); break;
	case 1504: LAUNCH_KERNEL(1504); break;
	case 1505: LAUNCH_KERNEL(1505); break;
	case 1506: LAUNCH_KERNEL(1506); break;
	case 1507: LAUNCH_KERNEL(1507); break;
	case 1508: LAUNCH_KERNEL(1508); break;
	case 1509: LAUNCH_KERNEL(1509); break;
	case 1510: LAUNCH_KERNEL(1510); break;
	case 1511: LAUNCH_KERNEL(1511); break;
	case 1512: LAUNCH_KERNEL(1512); break;
	case 1513: LAUNCH_KERNEL(1513); break;
	case 1514: LAUNCH_KERNEL(1514); break;
	case 1515: LAUNCH_KERNEL(1515); break;
	case 1516: LAUNCH_KERNEL(1516); break;
	case 1517: LAUNCH_KERNEL(1517); break;
	case 1518: LAUNCH_KERNEL(1518); break;
	case 1519: LAUNCH_KERNEL(1519); break;
	case 1520: LAUNCH_KERNEL(1520); break;
	case 1521: LAUNCH_KERNEL(1521); break;
	case 1522: LAUNCH_KERNEL(1522); break;
	case 1523: LAUNCH_KERNEL(1523); break;
	case 1524: LAUNCH_KERNEL(1524); break;
	case 1525: LAUNCH_KERNEL(1525); break;
	case 1526: LAUNCH_KERNEL(1526); break;
	case 1527: LAUNCH_KERNEL(1527); break;
	case 1528: LAUNCH_KERNEL(1528); break;
	case 1529: LAUNCH_KERNEL(1529); break;
	case 1530: LAUNCH_KERNEL(1530); break;
	case 1531: LAUNCH_KERNEL(1531); break;
	case 1532: LAUNCH_KERNEL(1532); break;
	case 1533: LAUNCH_KERNEL(1533); break;
	case 1534: LAUNCH_KERNEL(1534); break;
	case 1535: LAUNCH_KERNEL(1535); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
