#include <windows.h>
#include <stdio.h>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <sstream>
#include <iomanip>
 
#include "ADE32.h"
#include "cepluginsdk.h"
 
 
using namespace std;
 
 
DWORD dwTargetAddress;
 
ExportedFunctions Exported;


 
DWORD FindPattern(DWORD base, DWORD size, char pattern[], char mask[] )
{
	for( DWORD retAddress = base; retAddress < (base + size - strlen(mask)); retAddress++ )
	{
		if( *(BYTE*)retAddress == (pattern[0]&0xff) || mask[0] == '?' )
		{
			DWORD startSearch = retAddress;
			for( int i = 0; mask[i] != '\0' ; i++, startSearch++ )
			{
				if( (pattern[i]&0xff) != *(BYTE*)startSearch && mask[i] != '?')
					break;
				
				if( ((pattern[i]&0xff) == *(BYTE*)startSearch || mask[i] == '?') && mask[i+1] == '\0' )
					return retAddress;
			}        
		}
	}
 
	return NULL;
}
 
DWORD GetSizeOfAllocation(HANDLE hProcess, DWORD* pAddress)
{
	DWORD dwSize,
		  dwTemp;
	
	MEMORY_BASIC_INFORMATION info;
	
 
	dwSize = 0;
	dwTemp = (DWORD)pAddress;
	ZeroMemory(&info, sizeof(info));
 
	while(true)
	{
		VirtualQueryEx(hProcess, (LPCVOID)dwTemp, &info, sizeof(info));
 
		if((DWORD)info.AllocationBase == (DWORD)pAddress)
		{
			dwSize += info.RegionSize;
			dwTemp += info.RegionSize;
		}
		else
			break;
	}
 
	return dwSize;
}
 
DWORD GetAllocationBase(HANDLE hProcess, DWORD* pAddress)
{
	MEMORY_BASIC_INFORMATION info;
	
 
	ZeroMemory(&info, sizeof(info));
	VirtualQueryEx(hProcess, (LPCVOID)pAddress, &info, sizeof(info));
 
	return (DWORD)info.AllocationBase;
}
 
void ReadProcessMemorySafe(HANDLE hProcess, LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T size)
{
	SIZE_T tempSize,
		   bytesRead;
	
	do
	{
		tempSize = min(size, 0x1000);
 
		ReadProcessMemory(hProcess, lpAddress, lpBuffer, tempSize, &bytesRead);
 
		size -= tempSize;
		lpAddress = (LPCVOID)((DWORD)lpAddress + tempSize);
		lpBuffer = (LPVOID)((DWORD)lpBuffer + tempSize);
 
	}while(size != 0);
}
 
void SetClipboardText(string content)
{
	LPVOID pSpace;
 
	HGLOBAL hMemory;
 
	size_t length;
 
 
	length = content.length() + 1;
 
	hMemory = GlobalAlloc(GMEM_MOVEABLE, length);
 
	if(hMemory != NULL)
	{
		pSpace = GlobalLock(hMemory);
 
		if(pSpace != NULL)
		{
			memcpy(pSpace, content.c_str(), length);
 
			if(OpenClipboard(NULL) != FALSE)
			{
				if(EmptyClipboard() != FALSE)
				{
					SetClipboardData(CF_TEXT, hMemory);
					CloseClipboard();
				}
			}
			
			GlobalUnlock(hMemory);
		}
	}
}
	
 
 
BOOL WINAPI SignatureCallback(ULONG *selectedAddress)
{
	// for some reason, the selected address in the popup
	// callback isn't the selected address so its cached here
	dwTargetAddress = (DWORD)selectedAddress;
 
	return TRUE;
}
 
BOOL WINAPI SignaturePopupCallback(ULONG selectedAddress, char **addressofname)
{
	DWORD dwStartAddress,
		  dwSectionSize,
		  dwAddress,
		  dwTest,
		  dwCount,
		  dwTestOffset,
		  dwIndex,
		  dwDataSize;
 
	HANDLE hProcess;
	
	stringstream pattern;
 
	BYTE* pTargetMemory;
	
	disasm_struct ins;
		
	vector<BYTE> tempSig;
 
	string tempMask;
 
	int iMethod;
 
 
	if(Exported.OpenedProcessID != NULL && *Exported.OpenedProcessID != NULL)
	{
		// Open the process
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *Exported.OpenedProcessID);
 
		if(hProcess != NULL)
		{
			// Otherwise get the section base and size
			dwStartAddress = GetAllocationBase(hProcess, (DWORD*)dwTargetAddress);
 
			if(dwStartAddress != NULL)
				dwSectionSize = GetSizeOfAllocation(hProcess, (DWORD*)dwStartAddress);
 
			if(dwStartAddress != NULL && dwSectionSize != NULL)
			{
				pTargetMemory = (BYTE*)malloc(dwSectionSize);
 
				if(pTargetMemory != NULL)
				{
					// Copy the section for local testing
					ReadProcessMemorySafe(hProcess, (LPCVOID)dwStartAddress, pTargetMemory, dwSectionSize);
					
					tempMask = "";
					dwAddress = dwTargetAddress - dwStartAddress;
 
					while(true)
					{
						if(pTargetMemory + dwAddress < pTargetMemory + dwSectionSize - tempSig.size())
						{
							disasm(pTargetMemory + dwAddress, &ins);
 
							dwDataSize = ins.disasm_datasize;
 
 
							// guess if unsupported
 
							if(dwDataSize == 0)
								dwDataSize = ins.disasm_len - ((ins.disasm_flag & C_MODRM) == C_MODRM ? 2 : 1);
								
							if(ins.disasm_len > 0)
							{
								for(int i = 0; i < ins.disasm_len; i++)
								{
									if(i < ins.disasm_len - dwDataSize)
									{
										tempSig.push_back(*(BYTE*)(pTargetMemory + dwAddress + i));
										tempMask += "x";
									}
									else
									{
										tempSig.push_back(0);
										tempMask += "?";
									}
								}
 
								dwAddress += ins.disasm_len;
							}
							else
							{
								Exported.ShowMessage("Unable to disassemble instruction.");
								break;
							}
 
								
							// Test if its unique
 
							dwCount = 0;
							dwTest = (DWORD)pTargetMemory - 1;
 
							do
							{
								if(dwTest - (DWORD)pTargetMemory < dwSectionSize || foo == 0xFFFFFFFF)
								{
									dwTest = FindPattern(dwTest + 1, dwSectionSize - (dwTest - (DWORD)pTargetMemory), (char*)&tempSig[0], (char*)tempMask.c_str());
 
									if(dwTest != NULL)
										dwCount++;
								}
								else
									break;
 
							}while(dwTest != NULL && dwCount < 2);
 
 
							// If its unique
 
							if(dwCount == 1)
							{
								// trim excess
 
								do
								{
									if(tempMask.length() > 0 && tempMask[tempMask.length() - 1] == '?')
										tempMask.erase(tempMask.begin() + tempMask.length() - 1);
									else
										break;
 
								}while(true);
 
 
								iMethod = MessageBox(NULL, "Click \"Yes\" for Code Style\r\nClick \"No\" for IDA Style\r\nThe signature is copied to your clipboard", "SEGnosis Sig Maker", MB_YESNOCANCEL | MB_ICONQUESTION | MB_TOPMOST);
 
								if(iMethod == IDYES)
								{
									for(int i = 0; i < tempMask.length(); i++)
										pattern << "\\x" << setfill('0') << setw(2) << hex << (DWORD)tempSig[i];
 
									pattern << " " << tempMask;
										
									SetClipboardText(pattern.str());
								}
								else if(iMethod == IDNO)
								{
									for(int i = 0; i < tempMask.length(); i++)
									{
										if(tempMask[i] == 'x')
											pattern << setfill('0') << setw(2) << hex << (DWORD)tempSig[i];
										else
											pattern << "?";
 
										if(i != tempMask.length() - 1)
											pattern << " ";
									}
										
									SetClipboardText(pattern.str());
								}
									
								break;
							}
						}
						else
						{
							Exported.ShowMessage("Unable to find a unique signature.");
							break;
						}
					}
				}
				else
					Exported.ShowMessage("Unable to allocate memory.");
			}
			else
				Exported.ShowMessage("Selected address does not belong to a valid range of memory");
			
			CloseHandle(hProcess);
		}
		else
			Exported.ShowMessage("Unable to open a handle to process.");
	}
	else
		Exported.ShowMessage("No process selected.");
 
	return TRUE;
}
 
 
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	return TRUE;
}
 
 
#pragma comment(linker, "/EXPORT:CEPlugin_GetVersion=?CEPlugin_GetVersion@@YAHPEAU_PluginVersion@@H@Z")
__declspec(dllexport) BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion)
{
	pv->version = CESDK_VERSION;
	pv->pluginname = "CE SigMaker v1.0 (SDK version 4: 6.0+)";
 
	return TRUE;
}
 
#pragma comment(linker, "/EXPORT:CEPlugin_InitializePlugin=?CEPlugin_InitializePlugin@@YAHPEAU_ExportedFunctions@@H@Z")
__declspec(dllexport) BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid)
{
	BOOL bResult;
 
	int ContextPluginID;
 
	DISASSEMBLERCONTEXT_INIT init6;
 
 
	Exported = *ef;
	bResult = TRUE;
 
	if(Exported.sizeofExportedFunctions == sizeof(Exported))
	{
		init6.name = "Generate Signature";
		init6.shortcut = NULL;
		init6.shortcut = "Ctrl+Z";
		init6.callbackroutine = SignatureCallback;
		init6.callbackroutineOnPopup = SignaturePopupCallback;
 
		ContextPluginID = Exported.RegisterFunction(pluginid, ptDisassemblerContext, &init6);
 
		if (ContextPluginID != -1)
		{
		
		}
		else
		{
			Exported.ShowMessage("Unable to hook context menu");
			bResult = FALSE;
		}
	}
	else
	{
		Exported.ShowMessage("Version does not match");
		bResult = FALSE;
	}
 
	return bResult;
}
 
#pragma comment(linker, "/EXPORT:CEPlugin_DisablePlugin=?CEPlugin_DisablePlugin@@YAHXZ")
__declspec(dllexport) BOOL __stdcall CEPlugin_DisablePlugin()
{
	return TRUE;
}