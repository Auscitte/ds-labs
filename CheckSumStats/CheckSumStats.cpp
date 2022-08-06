/**
*   @file    CheckSumStats.cpp
*   @brief   A quick and dirty implementation of a utility collecting PE's CheckSum collision counts.
*
*   CheckSums are extracted from PE files and checked for validity with the help of CheckSumMappedFile()
*   function from ImageHlp. The utility creates two csv files, one containing collision counts for valid  
*   and another -- for invalid -- checksums. Non-zero invalid checksums are treated as suspicious and, hence,
*   additional information about them is recorded (in yet another csv): path to the binary, signer's name or
*   a remark that the binary is unsigned, and a Rich header presence indicator.
*   Csv format: <checksum vaue> <space> <collision count>
*               <path to the file> <tab> <signer's name> <tab> <rich header indicator>
*
*   @author     Ry Auscitte
*   @copyright  Ry Auscitte 2022 (the code is distributed under Apache 2.0 License) 
*/


#include <tchar.h>
#include <windows.h>
#include <imagehlp.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <map>
#include <list>
#include <string>
#include <iostream>
#include <fstream>
#include <stdarg.h>
#include <inttypes.h>
#include <intrin.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <Softpub.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "Crypt32.lib")


/**
* Encapsulates a collection of file mappings.
*
* MapViewOfFile() maps the entire file into the address space of the process an returns  
* a pointer to the first byte. FileMaps keeps track of all the handles created in the process.
* Call FreeFileMapping() when the mapping is no longer needed to release the resources. 
*/
struct FileMaps {
	std::map<PVOID, std::pair<HANDLE, HANDLE> > hashHandles;

	PVOID MapViewOfFile(LPCTSTR szFilePath)
	{
		HANDLE hFileToMap = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFileToMap == INVALID_HANDLE_VALUE)
			return NULL;

		HANDLE hMappedFile = CreateFileMapping(hFileToMap, 0, PAGE_READONLY, 0, 0, 0);
		if (hMappedFile == INVALID_HANDLE_VALUE) {
			CloseHandle(hFileToMap);
			return NULL;
		}

		LPVOID pDll = ::MapViewOfFile(hMappedFile, SECTION_MAP_READ, 0, 0, 0);
		if (pDll == NULL) {
			CloseHandle(hMappedFile);
			CloseHandle(hFileToMap);
			return NULL;
		}

		hashHandles[pDll] = std::pair<HANDLE, HANDLE>(hFileToMap, hMappedFile);

		return pDll;
	}

	HANDLE GetFileHandle(PVOID pMap)
	{
		if (hashHandles.find(pMap) == hashHandles.end())
			return INVALID_HANDLE_VALUE;

		return hashHandles[pMap].first;
	}

	void FreeFileMapping(PVOID pMap)
	{
		if (hashHandles.find(pMap) == hashHandles.end())
			return;

		UnmapViewOfFile(pMap);
		CloseHandle(hashHandles[pMap].second);
		CloseHandle(hashHandles[pMap].first);

		hashHandles.erase(pMap);
	}

	~FileMaps() 
	{
		auto it = hashHandles.begin();
		while (it != hashHandles.end()) {
			FreeFileMapping(it->first);
			it = hashHandles.begin();
		}
	}
};


typedef std::map<DWORD, DWORD> CountsHash;

#ifdef UNICODE
typedef std::wstring String;
#elif // UNICODE
typedef std::string String;
#endif

/**
* Holds checksum-related stats: collision counts and details of binaries with invalid checksums.
*
*/
struct ChecksumStats {
	int nGoodCount;
	int nBadCount;
	CountsHash hashGoodCounts;
	CountsHash hashBadCounts;
	std::list<String> lstrBadPaths;

	ChecksumStats():nGoodCount(0), nBadCount(0) {}
	
	static void InitCount(CountsHash& hash, DWORD dwCheckSum) 
	{
		//technically, it is an unnecessary step
		if (hash.find(dwCheckSum) == hash.end())
			hash[dwCheckSum] = 0;
	}

	static void DumpCounts(LPCTSTR szFileName, const CountsHash& hashCounts)
	{
		std::ofstream file;
		file.open(szFileName);
		for (auto it = hashCounts.begin(); it != hashCounts.end(); ++it)
			file << it->first << " " << it->second << std::endl;
		file.close();
	}

	void DumpBadPaths(LPCTSTR szFileName)
	{
#ifdef UNICODE
		std::wofstream file;
#elif
		std::ofstream file;
#endif
		file.open(szFileName);
		for (auto it = lstrBadPaths.cbegin(); it != lstrBadPaths.cend(); ++it)
			file << (*it) << std::endl;
		file.close();
	}

	void AddGoodCheckSum(DWORD dwCheckSum) 
	{
		nGoodCount++;
		InitCount(hashGoodCounts, dwCheckSum);
		hashGoodCounts[dwCheckSum]++;
	}

	void AddBadCheckSum(DWORD dwCheckSum) 
	{
		nBadCount++;
		InitCount(hashBadCounts, dwCheckSum);
		hashBadCounts[dwCheckSum]++;
	}

	void AddBadCheckSumDetailedRecord(int nFields,...)
	{
		va_list list;
		String sRec;
		va_start(list, nFields);
		for (int i = 0; i < nFields - 1; i++) {
			sRec += va_arg(list, String);
			sRec += TEXT("\t");
		} 
		if (nFields > 0)
			sRec += va_arg(list, String);
		va_end(list);

		lstrBadPaths.push_front(sRec);
	}
};

/**
* Returns a signer name for the cerificate.
*
*/
LPTSTR GetCertificateIssuerName(PCCERT_CONTEXT pCertCtx)
{
	DWORD dwStrType = CERT_SIMPLE_NAME_STR;
	DWORD dwCount = CertGetNameString(pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 
		0, &dwStrType, NULL, 0);
	if (dwCount == 0)
		return NULL;
	
	LPTSTR szIssuerName = (LPTSTR)malloc(dwCount * sizeof(TCHAR));
	if (CertGetNameString(pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0, &dwStrType, szIssuerName, dwCount) == 0)
		return NULL;
	
	return szIssuerName;
}

/**
* Checks if a PE file contains Rich header.
*
*/
BOOL ContainsRichHeader(PVOID pMap) 
{
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pMap;
	BYTE* pHdr = (BYTE*)pMap + pDosHdr->e_lfanew;

	const DWORD Rich = 0x68636952;
	while (*(DWORD*)pHdr != Rich && pHdr > ((BYTE*)pDosHdr + sizeof(IMAGE_DOS_HEADER)))
		pHdr--;

	return *(DWORD*)pHdr == Rich;
}

/**
* Checks if a PE file is signed and if it is, returns the signer's name.
*
* Many thanks to Mounir IDRASSI for sharing their knowledge 
* (https://groups.google.com/g/microsoft.public.platformsdk.security/c/OP4Wrrz4-9o)
*/
String VerifySignature(LPCWSTR pwszSourceFile, HANDLE hFile)
{
	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = hFile;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	memset(&WinTrustData, 0, sizeof(WinTrustData));
	WinTrustData.cbStruct = sizeof(WinTrustData);
	WinTrustData.dwUIChoice = WTD_UI_NONE;
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.pFile = &FileData;

	String res = String(TEXT("(error)"));

	LONG lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
	if (lStatus == ERROR_SUCCESS) {
		CRYPT_PROVIDER_DATA *pProvData = WTHelperProvDataFromStateData(WinTrustData.hWVTStateData);
		if (pProvData != NULL) {
			CRYPT_PROVIDER_SGNR  *pSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
			if (pSigner != NULL) {
				CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pSigner, 0);
				LPTSTR szIssuerName = GetCertificateIssuerName(pProvCert->pCert);
				res = String(szIssuerName);
				free(szIssuerName);
			}
		}
	}
	else {
		switch (lStatus)
		{
		case TRUST_E_NOSIGNATURE:
			res = String(TEXT("(no signature)"));
			break;
		case TRUST_E_EXPLICIT_DISTRUST:
			res = String(TEXT("(certificate not trusted)"));
			break;
		case TRUST_E_BAD_DIGEST:
			res = String(TEXT("(bad digest)"));
			break;
		case TRUST_E_TIME_STAMP:
			res = String(TEXT("(bad timestamp)"));
		}
	}

	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	return res;
}

/**
* An unoptimized (i.e. easy to undertand) implementation of the algorithm that computes PE checksum.
* 
*/
DWORD ComputeCheckSumUnoptimized(PVOID pMap, DWORD dwFileSize)
{
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pMap;
	IMAGE_NT_HEADERS* pHdr = (IMAGE_NT_HEADERS*)((BYTE*)pMap + pDosHdr->e_lfanew);
	
	//In the interest of the code being fundamentally correct (the offset is actually the same)
	DWORD dwCheckSumOffset = offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
		(pHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ?
			offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum) :
			offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum));

	uint16_t* pwChecksum = (uint16_t*)((BYTE*)pHdr + dwCheckSumOffset);
	
	DWORD dwSize = dwFileSize;
	uint16_t* pBase = (uint16_t*)(pMap); //16-bit!
	uint16_t wSum = 0;
	uint8_t bCarry = 0;

	while (dwSize >= sizeof(uint16_t)) {
		
		//Skipping the CheckSum Field
		if (pBase == pwChecksum) {
			pBase += 2;
			dwSize -= sizeof(uint32_t);
			continue;
		}

		dwSize -= sizeof(uint16_t);

		bCarry = _addcarry_u16(bCarry, wSum, *pBase++, &wSum);
	}

	if (dwSize != 0) {
		//the last byte, when the size of the file is not a multiple of two
		bCarry = _addcarry_u16(bCarry, wSum, *(BYTE*)pBase, &wSum);
	}

	//add a possible carry bit
	_addcarry_u16(bCarry, wSum, 0, &wSum);

	return wSum + dwFileSize;
}

/**
* Recursively enumerates files in the directory @szDirName (and its subdirectories) while
* collecting checksum-related stats for the PE files it encounters.
*
* @param szDirName root directory
* @param pStats holds the stats
* @param bCollectBadChecksums determines if additional information is collected for files with incorrect chechsums
*                             (Rich header presence bit and signer's name if signed)
*/
int EnumerateFiles(LPCTSTR szDirName, ChecksumStats* pStats, BOOL bCollectBadChecksums)
{
	String sDir(szDirName);
	sDir += TEXT("\\*");

	WIN32_FIND_DATA ffd;
	HANDLE hFind = FindFirstFile(sDir.c_str(), &ffd);

	if (INVALID_HANDLE_VALUE == hFind) {
		_tprintf(TEXT("\nFindFirstFile() failed with the error code %d on %s\n"), GetLastError(), sDir.c_str());
		return -1;
	}

	int ret = 0;
	do {
		if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			
			if (_tcscmp(ffd.cFileName, TEXT(".")) == 0 || _tcscmp(ffd.cFileName, TEXT("..")) == 0)
				continue;

			String sDirNext(szDirName);
			sDirNext += TEXT("\\");
			sDirNext += ffd.cFileName;
			
			int res = EnumerateFiles(sDirNext.c_str(), pStats, bCollectBadChecksums);
			if (res < 0)
				ret = res;
		}
		else {
			
			LPCTSTR szExt = PathFindExtension(ffd.cFileName);
			if (_tcscmp(szExt, TEXT(".exe")) != 0 && _tcscmp(szExt, TEXT(".EXE")) != 0 &&
				_tcscmp(szExt, TEXT(".dll")) != 0 && _tcscmp(szExt, TEXT(".DLL")) != 0 &&
				_tcscmp(szExt, TEXT(".sys")) != 0 && _tcscmp(szExt, TEXT(".SYS")) != 0)
				continue;

			if (ffd.nFileSizeHigh != 0) {

				_tprintf(TEXT("\nThe file is too large %s\n"), ffd.cFileName);
				continue;
			}

			String sFullPath(szDirName);
			sFullPath += TEXT("\\");
			sFullPath += ffd.cFileName;
			
			FileMaps mps;
			PVOID pMap = mps.MapViewOfFile(sFullPath.c_str());
			if (pMap == NULL)
				continue;

			DWORD dwHeaderSum = 0, dwCheckSum = 0;
			IMAGE_NT_HEADERS*  pHdrs = CheckSumMappedFile(pMap, ffd.nFileSizeLow, &dwHeaderSum, &dwCheckSum);
			
			if (pHdrs == NULL) 
				continue;

			if (dwHeaderSum == dwCheckSum)
				pStats->AddGoodCheckSum(dwCheckSum);
			else {
				pStats->AddBadCheckSum(dwHeaderSum);
				if (bCollectBadChecksums && dwHeaderSum > 0) {
					pStats->AddBadCheckSumDetailedRecord(3, sFullPath, 
						VerifySignature(sFullPath.c_str(), mps.GetFileHandle(pMap)), 
						String(ContainsRichHeader(pMap) ? TEXT("Rich Header") : TEXT("No Rich")));
				}
			}
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	FindClose(hFind);
	
	return ret;
}

enum ArgumentCounts {
	AC_EXENAME_ONLY = 1,
	AC_INCLUDE_INPUT_DIRECTORY,
	AC_INCLUDE_GOOD_CHECKSUM_COUNTS,
	AC_INCLUDE_BAD_CHECKSUM_COUNTS,
	AC_INCLUDE_BAD_CHECKSUM_DETAILS
};

int _tmain(int argc, TCHAR *argv[])
{
	if (argc <= AC_EXENAME_ONLY) {
		_tprintf(TEXT("\nUsage: %s <directory name> [<good checksum counts csv>][<bad checksum counts csv>][<bad checksum list>]\n"), argv[0]);
		return -1;
	}

	ChecksumStats stats;
	
 	int res = EnumerateFiles(argv[1], &stats, argc >= AC_INCLUDE_BAD_CHECKSUM_DETAILS);

	_tprintf(TEXT("\nFound %d binaries: %d with correct checksum and %d with incorrect\n"), 
		stats.nBadCount + stats.nGoodCount, stats.nGoodCount, stats.nBadCount);

	if (argc >= AC_INCLUDE_GOOD_CHECKSUM_COUNTS) {
		ChecksumStats::DumpCounts(argv[2], stats.hashGoodCounts);
	}

	if (argc >= AC_INCLUDE_BAD_CHECKSUM_COUNTS) {
		ChecksumStats::DumpCounts(argv[3], stats.hashBadCounts);
	}

	if (argc >= AC_INCLUDE_BAD_CHECKSUM_DETAILS) {
		stats.DumpBadPaths(argv[4]);
	}

	return res;
}
