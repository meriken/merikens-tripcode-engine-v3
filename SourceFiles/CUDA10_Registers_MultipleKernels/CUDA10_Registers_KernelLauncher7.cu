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

#define SALT 1792
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1793
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1794
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1795
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1796
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1797
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1798
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1799
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1800
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1801
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1802
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1803
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1804
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1805
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1806
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1807
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1808
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1809
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1810
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1811
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1812
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1813
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1814
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1815
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1816
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1817
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1818
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1819
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1820
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1821
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1822
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1823
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1824
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1825
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1826
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1827
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1828
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1829
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1830
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1831
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1832
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1833
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1834
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1835
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1836
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1837
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1838
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1839
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1840
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1841
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1842
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1843
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1844
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1845
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1846
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1847
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1848
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1849
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1850
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1851
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1852
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1853
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1854
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1855
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1856
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1857
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1858
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1859
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1860
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1861
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1862
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1863
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1864
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1865
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1866
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1867
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1868
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1869
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1870
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1871
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1872
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1873
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1874
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1875
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1876
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1877
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1878
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1879
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1880
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1881
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1882
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1883
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1884
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1885
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1886
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1887
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1888
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1889
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1890
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1891
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1892
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1893
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1894
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1895
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1896
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1897
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1898
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1899
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1900
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1901
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1902
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1903
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1904
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1905
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1906
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1907
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1908
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1909
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1910
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1911
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1912
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1913
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1914
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1915
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1916
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1917
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1918
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1919
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1920
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1921
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1922
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1923
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1924
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1925
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1926
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1927
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1928
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1929
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1930
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1931
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1932
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1933
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1934
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1935
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1936
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1937
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1938
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1939
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1940
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1941
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1942
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1943
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1944
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1945
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1946
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1947
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1948
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1949
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1950
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1951
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1952
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1953
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1954
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1955
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1956
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1957
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1958
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1959
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1960
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1961
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1962
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1963
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1964
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1965
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1966
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1967
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1968
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1969
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1970
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1971
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1972
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1973
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1974
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1975
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1976
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1977
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1978
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1979
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1980
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1981
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1982
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1983
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1984
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1985
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1986
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1987
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1988
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1989
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1990
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1991
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1992
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1993
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1994
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1995
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1996
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1997
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1998
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1999
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2000
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2001
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2002
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2003
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2004
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2005
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2006
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2007
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2008
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2009
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2010
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2011
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2012
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2013
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2014
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2015
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2016
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2017
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2018
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2019
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2020
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2021
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2022
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2023
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2024
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2025
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2026
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2027
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2028
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2029
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2030
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2031
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2032
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2033
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2034
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2035
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2036
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2037
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2038
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2039
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2040
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2041
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2042
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2043
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2044
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2045
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2046
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2047
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher7()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel7(
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
	case 1792: LAUNCH_KERNEL(1792); break;
	case 1793: LAUNCH_KERNEL(1793); break;
	case 1794: LAUNCH_KERNEL(1794); break;
	case 1795: LAUNCH_KERNEL(1795); break;
	case 1796: LAUNCH_KERNEL(1796); break;
	case 1797: LAUNCH_KERNEL(1797); break;
	case 1798: LAUNCH_KERNEL(1798); break;
	case 1799: LAUNCH_KERNEL(1799); break;
	case 1800: LAUNCH_KERNEL(1800); break;
	case 1801: LAUNCH_KERNEL(1801); break;
	case 1802: LAUNCH_KERNEL(1802); break;
	case 1803: LAUNCH_KERNEL(1803); break;
	case 1804: LAUNCH_KERNEL(1804); break;
	case 1805: LAUNCH_KERNEL(1805); break;
	case 1806: LAUNCH_KERNEL(1806); break;
	case 1807: LAUNCH_KERNEL(1807); break;
	case 1808: LAUNCH_KERNEL(1808); break;
	case 1809: LAUNCH_KERNEL(1809); break;
	case 1810: LAUNCH_KERNEL(1810); break;
	case 1811: LAUNCH_KERNEL(1811); break;
	case 1812: LAUNCH_KERNEL(1812); break;
	case 1813: LAUNCH_KERNEL(1813); break;
	case 1814: LAUNCH_KERNEL(1814); break;
	case 1815: LAUNCH_KERNEL(1815); break;
	case 1816: LAUNCH_KERNEL(1816); break;
	case 1817: LAUNCH_KERNEL(1817); break;
	case 1818: LAUNCH_KERNEL(1818); break;
	case 1819: LAUNCH_KERNEL(1819); break;
	case 1820: LAUNCH_KERNEL(1820); break;
	case 1821: LAUNCH_KERNEL(1821); break;
	case 1822: LAUNCH_KERNEL(1822); break;
	case 1823: LAUNCH_KERNEL(1823); break;
	case 1824: LAUNCH_KERNEL(1824); break;
	case 1825: LAUNCH_KERNEL(1825); break;
	case 1826: LAUNCH_KERNEL(1826); break;
	case 1827: LAUNCH_KERNEL(1827); break;
	case 1828: LAUNCH_KERNEL(1828); break;
	case 1829: LAUNCH_KERNEL(1829); break;
	case 1830: LAUNCH_KERNEL(1830); break;
	case 1831: LAUNCH_KERNEL(1831); break;
	case 1832: LAUNCH_KERNEL(1832); break;
	case 1833: LAUNCH_KERNEL(1833); break;
	case 1834: LAUNCH_KERNEL(1834); break;
	case 1835: LAUNCH_KERNEL(1835); break;
	case 1836: LAUNCH_KERNEL(1836); break;
	case 1837: LAUNCH_KERNEL(1837); break;
	case 1838: LAUNCH_KERNEL(1838); break;
	case 1839: LAUNCH_KERNEL(1839); break;
	case 1840: LAUNCH_KERNEL(1840); break;
	case 1841: LAUNCH_KERNEL(1841); break;
	case 1842: LAUNCH_KERNEL(1842); break;
	case 1843: LAUNCH_KERNEL(1843); break;
	case 1844: LAUNCH_KERNEL(1844); break;
	case 1845: LAUNCH_KERNEL(1845); break;
	case 1846: LAUNCH_KERNEL(1846); break;
	case 1847: LAUNCH_KERNEL(1847); break;
	case 1848: LAUNCH_KERNEL(1848); break;
	case 1849: LAUNCH_KERNEL(1849); break;
	case 1850: LAUNCH_KERNEL(1850); break;
	case 1851: LAUNCH_KERNEL(1851); break;
	case 1852: LAUNCH_KERNEL(1852); break;
	case 1853: LAUNCH_KERNEL(1853); break;
	case 1854: LAUNCH_KERNEL(1854); break;
	case 1855: LAUNCH_KERNEL(1855); break;
	case 1856: LAUNCH_KERNEL(1856); break;
	case 1857: LAUNCH_KERNEL(1857); break;
	case 1858: LAUNCH_KERNEL(1858); break;
	case 1859: LAUNCH_KERNEL(1859); break;
	case 1860: LAUNCH_KERNEL(1860); break;
	case 1861: LAUNCH_KERNEL(1861); break;
	case 1862: LAUNCH_KERNEL(1862); break;
	case 1863: LAUNCH_KERNEL(1863); break;
	case 1864: LAUNCH_KERNEL(1864); break;
	case 1865: LAUNCH_KERNEL(1865); break;
	case 1866: LAUNCH_KERNEL(1866); break;
	case 1867: LAUNCH_KERNEL(1867); break;
	case 1868: LAUNCH_KERNEL(1868); break;
	case 1869: LAUNCH_KERNEL(1869); break;
	case 1870: LAUNCH_KERNEL(1870); break;
	case 1871: LAUNCH_KERNEL(1871); break;
	case 1872: LAUNCH_KERNEL(1872); break;
	case 1873: LAUNCH_KERNEL(1873); break;
	case 1874: LAUNCH_KERNEL(1874); break;
	case 1875: LAUNCH_KERNEL(1875); break;
	case 1876: LAUNCH_KERNEL(1876); break;
	case 1877: LAUNCH_KERNEL(1877); break;
	case 1878: LAUNCH_KERNEL(1878); break;
	case 1879: LAUNCH_KERNEL(1879); break;
	case 1880: LAUNCH_KERNEL(1880); break;
	case 1881: LAUNCH_KERNEL(1881); break;
	case 1882: LAUNCH_KERNEL(1882); break;
	case 1883: LAUNCH_KERNEL(1883); break;
	case 1884: LAUNCH_KERNEL(1884); break;
	case 1885: LAUNCH_KERNEL(1885); break;
	case 1886: LAUNCH_KERNEL(1886); break;
	case 1887: LAUNCH_KERNEL(1887); break;
	case 1888: LAUNCH_KERNEL(1888); break;
	case 1889: LAUNCH_KERNEL(1889); break;
	case 1890: LAUNCH_KERNEL(1890); break;
	case 1891: LAUNCH_KERNEL(1891); break;
	case 1892: LAUNCH_KERNEL(1892); break;
	case 1893: LAUNCH_KERNEL(1893); break;
	case 1894: LAUNCH_KERNEL(1894); break;
	case 1895: LAUNCH_KERNEL(1895); break;
	case 1896: LAUNCH_KERNEL(1896); break;
	case 1897: LAUNCH_KERNEL(1897); break;
	case 1898: LAUNCH_KERNEL(1898); break;
	case 1899: LAUNCH_KERNEL(1899); break;
	case 1900: LAUNCH_KERNEL(1900); break;
	case 1901: LAUNCH_KERNEL(1901); break;
	case 1902: LAUNCH_KERNEL(1902); break;
	case 1903: LAUNCH_KERNEL(1903); break;
	case 1904: LAUNCH_KERNEL(1904); break;
	case 1905: LAUNCH_KERNEL(1905); break;
	case 1906: LAUNCH_KERNEL(1906); break;
	case 1907: LAUNCH_KERNEL(1907); break;
	case 1908: LAUNCH_KERNEL(1908); break;
	case 1909: LAUNCH_KERNEL(1909); break;
	case 1910: LAUNCH_KERNEL(1910); break;
	case 1911: LAUNCH_KERNEL(1911); break;
	case 1912: LAUNCH_KERNEL(1912); break;
	case 1913: LAUNCH_KERNEL(1913); break;
	case 1914: LAUNCH_KERNEL(1914); break;
	case 1915: LAUNCH_KERNEL(1915); break;
	case 1916: LAUNCH_KERNEL(1916); break;
	case 1917: LAUNCH_KERNEL(1917); break;
	case 1918: LAUNCH_KERNEL(1918); break;
	case 1919: LAUNCH_KERNEL(1919); break;
	case 1920: LAUNCH_KERNEL(1920); break;
	case 1921: LAUNCH_KERNEL(1921); break;
	case 1922: LAUNCH_KERNEL(1922); break;
	case 1923: LAUNCH_KERNEL(1923); break;
	case 1924: LAUNCH_KERNEL(1924); break;
	case 1925: LAUNCH_KERNEL(1925); break;
	case 1926: LAUNCH_KERNEL(1926); break;
	case 1927: LAUNCH_KERNEL(1927); break;
	case 1928: LAUNCH_KERNEL(1928); break;
	case 1929: LAUNCH_KERNEL(1929); break;
	case 1930: LAUNCH_KERNEL(1930); break;
	case 1931: LAUNCH_KERNEL(1931); break;
	case 1932: LAUNCH_KERNEL(1932); break;
	case 1933: LAUNCH_KERNEL(1933); break;
	case 1934: LAUNCH_KERNEL(1934); break;
	case 1935: LAUNCH_KERNEL(1935); break;
	case 1936: LAUNCH_KERNEL(1936); break;
	case 1937: LAUNCH_KERNEL(1937); break;
	case 1938: LAUNCH_KERNEL(1938); break;
	case 1939: LAUNCH_KERNEL(1939); break;
	case 1940: LAUNCH_KERNEL(1940); break;
	case 1941: LAUNCH_KERNEL(1941); break;
	case 1942: LAUNCH_KERNEL(1942); break;
	case 1943: LAUNCH_KERNEL(1943); break;
	case 1944: LAUNCH_KERNEL(1944); break;
	case 1945: LAUNCH_KERNEL(1945); break;
	case 1946: LAUNCH_KERNEL(1946); break;
	case 1947: LAUNCH_KERNEL(1947); break;
	case 1948: LAUNCH_KERNEL(1948); break;
	case 1949: LAUNCH_KERNEL(1949); break;
	case 1950: LAUNCH_KERNEL(1950); break;
	case 1951: LAUNCH_KERNEL(1951); break;
	case 1952: LAUNCH_KERNEL(1952); break;
	case 1953: LAUNCH_KERNEL(1953); break;
	case 1954: LAUNCH_KERNEL(1954); break;
	case 1955: LAUNCH_KERNEL(1955); break;
	case 1956: LAUNCH_KERNEL(1956); break;
	case 1957: LAUNCH_KERNEL(1957); break;
	case 1958: LAUNCH_KERNEL(1958); break;
	case 1959: LAUNCH_KERNEL(1959); break;
	case 1960: LAUNCH_KERNEL(1960); break;
	case 1961: LAUNCH_KERNEL(1961); break;
	case 1962: LAUNCH_KERNEL(1962); break;
	case 1963: LAUNCH_KERNEL(1963); break;
	case 1964: LAUNCH_KERNEL(1964); break;
	case 1965: LAUNCH_KERNEL(1965); break;
	case 1966: LAUNCH_KERNEL(1966); break;
	case 1967: LAUNCH_KERNEL(1967); break;
	case 1968: LAUNCH_KERNEL(1968); break;
	case 1969: LAUNCH_KERNEL(1969); break;
	case 1970: LAUNCH_KERNEL(1970); break;
	case 1971: LAUNCH_KERNEL(1971); break;
	case 1972: LAUNCH_KERNEL(1972); break;
	case 1973: LAUNCH_KERNEL(1973); break;
	case 1974: LAUNCH_KERNEL(1974); break;
	case 1975: LAUNCH_KERNEL(1975); break;
	case 1976: LAUNCH_KERNEL(1976); break;
	case 1977: LAUNCH_KERNEL(1977); break;
	case 1978: LAUNCH_KERNEL(1978); break;
	case 1979: LAUNCH_KERNEL(1979); break;
	case 1980: LAUNCH_KERNEL(1980); break;
	case 1981: LAUNCH_KERNEL(1981); break;
	case 1982: LAUNCH_KERNEL(1982); break;
	case 1983: LAUNCH_KERNEL(1983); break;
	case 1984: LAUNCH_KERNEL(1984); break;
	case 1985: LAUNCH_KERNEL(1985); break;
	case 1986: LAUNCH_KERNEL(1986); break;
	case 1987: LAUNCH_KERNEL(1987); break;
	case 1988: LAUNCH_KERNEL(1988); break;
	case 1989: LAUNCH_KERNEL(1989); break;
	case 1990: LAUNCH_KERNEL(1990); break;
	case 1991: LAUNCH_KERNEL(1991); break;
	case 1992: LAUNCH_KERNEL(1992); break;
	case 1993: LAUNCH_KERNEL(1993); break;
	case 1994: LAUNCH_KERNEL(1994); break;
	case 1995: LAUNCH_KERNEL(1995); break;
	case 1996: LAUNCH_KERNEL(1996); break;
	case 1997: LAUNCH_KERNEL(1997); break;
	case 1998: LAUNCH_KERNEL(1998); break;
	case 1999: LAUNCH_KERNEL(1999); break;
	case 2000: LAUNCH_KERNEL(2000); break;
	case 2001: LAUNCH_KERNEL(2001); break;
	case 2002: LAUNCH_KERNEL(2002); break;
	case 2003: LAUNCH_KERNEL(2003); break;
	case 2004: LAUNCH_KERNEL(2004); break;
	case 2005: LAUNCH_KERNEL(2005); break;
	case 2006: LAUNCH_KERNEL(2006); break;
	case 2007: LAUNCH_KERNEL(2007); break;
	case 2008: LAUNCH_KERNEL(2008); break;
	case 2009: LAUNCH_KERNEL(2009); break;
	case 2010: LAUNCH_KERNEL(2010); break;
	case 2011: LAUNCH_KERNEL(2011); break;
	case 2012: LAUNCH_KERNEL(2012); break;
	case 2013: LAUNCH_KERNEL(2013); break;
	case 2014: LAUNCH_KERNEL(2014); break;
	case 2015: LAUNCH_KERNEL(2015); break;
	case 2016: LAUNCH_KERNEL(2016); break;
	case 2017: LAUNCH_KERNEL(2017); break;
	case 2018: LAUNCH_KERNEL(2018); break;
	case 2019: LAUNCH_KERNEL(2019); break;
	case 2020: LAUNCH_KERNEL(2020); break;
	case 2021: LAUNCH_KERNEL(2021); break;
	case 2022: LAUNCH_KERNEL(2022); break;
	case 2023: LAUNCH_KERNEL(2023); break;
	case 2024: LAUNCH_KERNEL(2024); break;
	case 2025: LAUNCH_KERNEL(2025); break;
	case 2026: LAUNCH_KERNEL(2026); break;
	case 2027: LAUNCH_KERNEL(2027); break;
	case 2028: LAUNCH_KERNEL(2028); break;
	case 2029: LAUNCH_KERNEL(2029); break;
	case 2030: LAUNCH_KERNEL(2030); break;
	case 2031: LAUNCH_KERNEL(2031); break;
	case 2032: LAUNCH_KERNEL(2032); break;
	case 2033: LAUNCH_KERNEL(2033); break;
	case 2034: LAUNCH_KERNEL(2034); break;
	case 2035: LAUNCH_KERNEL(2035); break;
	case 2036: LAUNCH_KERNEL(2036); break;
	case 2037: LAUNCH_KERNEL(2037); break;
	case 2038: LAUNCH_KERNEL(2038); break;
	case 2039: LAUNCH_KERNEL(2039); break;
	case 2040: LAUNCH_KERNEL(2040); break;
	case 2041: LAUNCH_KERNEL(2041); break;
	case 2042: LAUNCH_KERNEL(2042); break;
	case 2043: LAUNCH_KERNEL(2043); break;
	case 2044: LAUNCH_KERNEL(2044); break;
	case 2045: LAUNCH_KERNEL(2045); break;
	case 2046: LAUNCH_KERNEL(2046); break;
	case 2047: LAUNCH_KERNEL(2047); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
