#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "Crypt32")
/* 
	Extracts Wifi Keys from a Windows computer.	
*/
static int len;

void logo() {
	printf("###   Wifi Key Extractor   ###\n");
	printf("###   Written by: Luke Jacobs ###\n");
}

char *Spacify(char *str) {
	int i, i2 = 0, x = 0;
	static char *out; out = (char *) calloc(strlen(str)*2, 1);
	for (i = 0; i < strlen(str); i++) {
		if (((x+1) % 3) == 0) {
			out[x] = 0x20;
			x++; 
		}
		out[x] = str[i2]; 
		i2++; x++;
	}
	return out;
}
char *Encrypt(char *dec) {
	DATA_BLOB decBlob, encBlob;
	decBlob.pbData = (BYTE *) dec;
	decBlob.cbData = (DWORD) strlen(dec);
	
	if (CryptProtectData(&decBlob, NULL, NULL, NULL, NULL, 0, &encBlob)) {
		len = (int) encBlob.cbData;
		return (char *) encBlob.pbData;
	} else {
		return "Error";
	}
}
char *Decrypt(char *enc) {
	int i = 0; char *pEnd;
	char *enc2; enc2 = calloc(strlen(enc)/2, 1); 
	enc2[i] = strtol(enc, &pEnd, 16);
	float limit; limit = strlen(enc)/3;
	for (i = 1; i < limit+1; i++) {
		enc2[i] = strtol(pEnd, &pEnd, 16);
	}
	DATA_BLOB encBlob, decBlob;
	encBlob.pbData = (BYTE *) enc2;
	encBlob.cbData = (DWORD) strlen(enc)/2;
	
	if (CryptUnprotectData(&encBlob, NULL, NULL, NULL, NULL, 0, &decBlob)) {
		static char *out; 
		out = (char *) calloc(decBlob.cbData, 1);
		strncpy(out, decBlob.pbData, decBlob.cbData);
		return out;
	} else {
		return "Error";
	}
}

char *Retrieve(char *str, char *start, char *end) {
	int i;
	char *pStart; char *pEnd;
	static char *out;
	
	if ((strstr(str, start) == NULL) || (strstr(str, end) == NULL))
		return "null";
	out = calloc(strlen(str), 1);
	pStart = strstr(str, start);
	pEnd = strstr(str, end);
	strcpy(out, pStart+strlen(start)); 
	out[strlen(out)-strlen(pEnd)] = 0; 
	return out;
}

int  Extract(char *xmlDoc) {
	//Look for SSIDS
	char *ssid; ssid = Retrieve(xmlDoc, "<name>", "</name>");
	printf("\n[+] SSID: %s");

	//Look for keys
	char *key; key = Retrieve(xmlDoc, "<keyMaterial>", "</keyMaterial>");
	printf("\n| KEY: %s\n", key);
	
	//Decrypt
	printf("| DECRYPTED: %s\n", Decrypt(Spacify(key)));
	return 1;
}

void Analyze(char *FileName) {
	char *InputBuffer; InputBuffer = (char *) calloc(5000, 1);
	FILE *fp;
	fp = fopen(FileName, "r");
	if (fp == NULL) {
		printf("Error: Cant open file, %d\n", GetLastError());
		exit(1);
	}
	fread(InputBuffer, 1, 4999, fp);
	Extract(InputBuffer);
	return;
}

void Search(char *Directory) {
	char *FullDir; FullDir = (char *) calloc(MAX_PATH, 1);
	WIN32_FIND_DATA FindFileData3;
	HANDLE hFind3;
	if (Directory[0] == 0)
		return;
	hFind3 = FindFirstFile(Directory, &FindFileData3);
	if (hFind3 == INVALID_HANDLE_VALUE) {
		printf("Error: Directory (%s) empty!\n", Directory);
		return;
	}
	while (FindNextFile(hFind3, &FindFileData3)) {
		if (!strcmp(FindFileData3.cFileName, ".."))
			continue;
		strcpy(FullDir, Directory); FullDir[strlen(FullDir)-1] = 0;
		sprintf(FullDir, "%s%s", FullDir, FindFileData3.cFileName);
		Analyze(FullDir);
	}
	return;
}

int main(int argc, char *argv[]) {
	logo();
	int i = 0, i2;
	char DirFileNames[50][MAX_PATH];
	char *win7path = "c:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\*";
	
	//Put Master Directories into DirFileNames
	WIN32_FIND_DATA FindFileData, FindFileData2;
	HANDLE hFind, hFind2;
	hFind = FindFirstFile(win7path, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		printf("Error: directory empty\n");
		return -1;
	} 
	sprintf(DirFileNames[i], "c:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\%s\\*", FindFileData.cFileName);
	for (i = 1; FindNextFile(hFind, &FindFileData); i++) {
		sprintf(DirFileNames[i], "c:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\%s\\*", FindFileData.cFileName);
	}
	
	//Analyze all items
	for (i2 = 0; i2 != i; i2++) {
		Search(DirFileNames[i2+2]);
	}
	
	return 0;
}

