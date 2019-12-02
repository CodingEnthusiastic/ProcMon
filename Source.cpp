//Process Monitoring Tool
using namespace std;

#include <sys/types.h>
#include <sys/stat.h>
#include<iostream>
#include<string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <io.h>

//structure for the inputs from main function
typedef struct LogFile
{
	char ProcessName[100];
	unsigned int pid;
	unsigned int ppid;
	unsigned int thread_cnt;
}LOGFILE;

//Thread info parent class
class ThreadInfo
{
private:
	DWORD PID;
	HANDLE hThreadSnap;
	THREADENTRY32 te32;
public:
	ThreadInfo(DWORD);
	BOOL ThreadsDisplay();
	WCHAR   szModule[MAX_MODULE_NAME32 + 1];
};

////////////////////////////////////////////////////////////////////////////////////
//Constructor name: 	ThreadInfo
//Parameters:		DWORD no		
//Description:		Constructor of the class ThreadInfo,
//			displays the size of the thread entry,
//			if the value of hProcessSnap is invalid then its gives error message
////////////////////////////////////////////////////////////////////////////////////
ThreadInfo::ThreadInfo(DWORD no)
{
	PID = no;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		cout << "Unable to create the snapshot of current thread pool" << endl;
		return;
	}
	te32.dwSize = sizeof(THREADENTRY32);
}


///////////////////////////////////////////////////////////////////////////////////
//Function name: 	ThreadsDisplay
//Function date: 	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		NONE
//			
//Description:		It displays the threads of the processes
//Return value: 	Boolean
//Returns TRUE if the displayed the threads
//Else Returns FALSE if any error
////////////////////////////////////////////////////////////////////////////////////
BOOL ThreadInfo::ThreadsDisplay()
{
	if (!Thread32First(hThreadSnap, &te32))
	{
		cout << "Error: In Getting the first thread" << endl;
		CloseHandle(hThreadSnap);
		return FALSE;
	}
	cout << endl << "THREAD OF THIS PROCESS:" << endl;

	do
	{
		if (te32.th32OwnerProcessID == PID)
		{
			cout << "\tTHREAD ID : " << te32.th32ThreadID << endl;
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

//DLL Info parent class
class DLLInfo
{
private:
	DWORD PID;
	MODULEENTRY32 me32;
	HANDLE hProcessSnap;
public:
	DLLInfo(DWORD);
	BOOL DependentDLLDisplay();
	WCHAR   szModule[MAX_MODULE_NAME32 + 1];
};

////////////////////////////////////////////////////////////////////////////////////
//Constructor name: 	DLLInfo
//Parameters:		DWORD no			
//Description:		Constructor of the class DLLInfo,
//			displays the size of the module entry,
//			if the value of hProcessSnap is invalid then its gives error message
////////////////////////////////////////////////////////////////////////////////////

DLLInfo::DLLInfo(DWORD no)
{
	PID = no;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout << "Error: Unable to create the snapshot of current thread pool" << endl;
		return;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
}


////////////////////////////////////////////////////////////////////////////////////
//Function name: 	DependentDLLDisplay
//Function date: 	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		NONE
//			
//Description:		Displays dependent dynamic linked library of the process.  
//Return value: 	Boolean
//Returns TRUE if the dependent DLL array is obtained
//Else Returns FALSE if any error
////////////////////////////////////////////////////////////////////////////////////
BOOL DLLInfo::DependentDLLDisplay()
{
	char arr[200];

	if (!Module32First(hProcessSnap, &me32))
	{
		cout << "FAILED to get DLL information" << endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	cout << "DEPENDENT DLL OF THIS PROCESS" << endl;
	do
	{
		wcstombs(arr,szModule, 200);
		cout << arr << endl;
	} while (Module32Next(hProcessSnap, &me32));

	CloseHandle(hProcessSnap);
	return TRUE;
}

//Process Info parent class
class ProcessInfo
{
private:
	DWORD PID;
	DLLInfo* pdobj;
	ThreadInfo* ptobj;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
public:
	ProcessInfo();
	BOOL ProcessDisplay(string);
	BOOL ProcessLog();
	BOOL ReadLog(DWORD, DWORD, DWORD, DWORD);
	BOOL ProcessSearch(char*);
	BOOL KillProcess(char*);
	WCHAR   szExeFile[MAX_MODULE_NAME32 + 1];
};


////////////////////////////////////////////////////////////////////////////////////
//Constructor name: 	ProcessInfo
//Parameters:		NONE			
//Description:		Constructor of the class ProcessInfo,
//			displays the size of the process entry,
//			if the value of hProcessSnap is invalid then its gives error message
////////////////////////////////////////////////////////////////////////////////////
ProcessInfo::ProcessInfo()
{
	ptobj = NULL;
	pdobj = NULL;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout << "Error : Unable to create the snapdhot of running processes" << endl;
		return;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
}


////////////////////////////////////////////////////////////////////////////////////
//Function name: 	ProcessLog
//Function date: 	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		NONE			
//Description:		It gives the process log information about the processes.
//Return value: 	Boolean
//Returns TRUE if the log is successfully returned.
//Else Returns FALSE if any error
////////////////////////////////////////////////////////////////////////////////////

BOOL ProcessInfo::ProcessLog()
{
	const char* month[] = { "JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC" };
	char FileName[50], arr[512];
	int ret = 0, fd = 0, count = 0;

	SYSTEMTIME lt;
	LOGFILE fobj;
	FILE* fp;

	GetLocalTime(&lt);
	sprintf_s(FileName, "C://MarvellousLog %02d_%02d_%02d%s.txt", lt.wHour, lt.wMinute, lt.wDay, month[lt.wMonth - 1]);
	fp = fopen(FileName, "wb");
	if (fp == NULL)
	{
		cout << "Unable to create log file" << endl;
		return FALSE;
	}
	else
	{
		cout << "Log file succesfully gets created as : " << FileName << endl;
		cout << "Time of log file creation is->" << lt.wHour << ":" << lt.wMinute << ":" << lt.wDay << "th " << month[lt.wMonth - 1] << endl;
	}

	if (!Process32First(hProcessSnap, &pe32))
	{
		cout << "Error: In finding the first process." << endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	do
	{
		wcstombs_s(NULL, arr, 200, szExeFile, 200);
		strcpy_s(fobj.ProcessName, arr);
		fobj.pid = pe32.th32ProcessID;
		fobj.ppid = pe32.th32ParentProcessID;
		fobj.thread_cnt = pe32.cntThreads;
		fwrite(&fobj, sizeof(fobj), 1, fp);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	fclose(fp);
	return TRUE;
}



////////////////////////////////////////////////////////////////////////////////////
//Function name: 	ProcessDisplay
//Function date: 	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		char* option
//			
//Description:		This function displays the processes information on the basis of options
//			if user gives -a then it display all the details,
//			if user gives -d then it displays specific process information
//Return value: 	Boolean
//Returns TRUE if the 
//Else Returns FALSE if any error
////////////////////////////////////////////////////////////////////////////////////

BOOL ProcessInfo::ProcessDisplay(string option)
{

	char arr[200];
	if (!Process32First(hProcessSnap, &pe32))
	{
		cout << "Error: In finding the first process." << endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		cout << endl << "------------------------------------------------------------";
		wcstombs_s(NULL, arr, 200, szExeFile, 200);
		cout << endl << "PROCESS NAME: " << arr;
		cout << endl << "PID:" << pe32.th32ProcessID;
		cout << endl << "Parent PID: " << pe32.th32ParentProcessID;
		cout << endl << "No of Thread: " << pe32.cntThreads;

		if ((option.compare("-a") == 0) || (option.compare("-d") == 0) || (option.compare("-t") == 0))
		{
			if ((option.compare("-t") == 0) || (option.compare("-a") == 0))
			{
				ptobj = new ThreadInfo(pe32.th32ProcessID);
				ptobj->ThreadsDisplay();
				delete ptobj;
			}
			if ((option.compare("-d") == 0) || (option.compare("-a") == 0))
			{
				pdobj = new DLLInfo(pe32.th32ProcessID);
				pdobj->DependentDLLDisplay();
				delete pdobj;
			}
		}

		cout << endl << "------------------------------------------------------------";
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return TRUE;
}


////////////////////////////////////////////////////////////////////////////////////
//Function name: 	ReadLog
//Function date: 	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		DWORD hr,DWORD min,DWORD date,DWORD month
//			
//Description:		It gives the log information by taking the date,hour,month,min as input from the user. 
//Return value: 	Boolean
//Returns TRUE if the readlog is performed successfully
//Else Returns FALSE if any error
////////////////////////////////////////////////////////////////////////////////////

BOOL ProcessInfo::ReadLog(DWORD hr, DWORD min, DWORD date, DWORD month)
{
	char FileName[50];
	const char* montharr[] = { "JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC" };
	int ret = 0, count = 0;
	LOGFILE fobj;
	FILE* fp;

	sprintf_s(FileName, "C://MarvellousLog %02d_%02d_%02d %s.txt", hr, min, date, montharr[month - 1]);

	fp = fopen(FileName, "rb");
	if (fp == NULL)
	{
		cout << "Error : Unable to open log file named as :" << FileName << endl;
		return FALSE;
	}
	while ((ret = fread(&fobj, 1, sizeof(fobj), fp)) != 0)
	{
		cout << "--------------------------------------------------------------" << endl;
		cout << "Process Name :" << fobj.ProcessName << endl;
		cout << "PID of current process :" << fobj.pid << endl;
		cout << "Parent process PID :" << fobj.ppid << endl;
		cout << "Thread count of process :" << fobj.thread_cnt << endl;
	}

	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////
//Function name: 	ProcessSearch
//Function date: 	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		char *name
//			It takes the process name which is to be search by the function
//Description:		This function performs the search operation of the process 
//			and displays its contents
//Return value: 	Boolean
//Returns TRUE if the process search is performed successfully
//Else Returns FALSE if any error
////////////////////////////////////////////////////////////////////////////////////

BOOL ProcessInfo::ProcessSearch(char* name)
{

	char arr[200];
	BOOL Flag = FALSE;

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		wcstombs_s(NULL, arr, 200, szExeFile, 200);
		if (_stricmp(arr, name) == 0)
		{
			cout << endl << "PROCESS NAME: " << arr;
			cout << endl << "PID:" << pe32.th32ProcessID;
			cout << endl << "Parent PID: " << pe32.th32ParentProcessID;
			cout << endl << "No of Thread: " << pe32.cntThreads;
			Flag = TRUE;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return Flag;
}

////////////////////////////////////////////////////////////////////////////////////
//Function name: 	KillProcess
//Function date: 	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		char *name
//			It takes the process name which is to be killed explicitly
//Description:		This function kills the running process,
//			if the process id is -1 it indicates there is no such process,
//			if the hprocess parameter is null then 
//			there is no permission to terminate the process 
//Return value: 	Boolean
//Returns TRUE if the process is killed successfully
//Else Returns FALSE if any error
////////////////////////////////////////////////////////////////////////////////////

BOOL ProcessInfo::KillProcess(char* name)
{
	char arr[200];
	int pid = -1;
	BOOL bret;
	HANDLE hprocess;

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		wcstombs_s(NULL, arr, 200, szExeFile, 200);
		if (_stricmp(arr, name) == 0)
		{
			pid = pe32.th32ProcessID;
			break;
		}

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	if (pid == -1)
	{
		cout << "ERROR : There is no such process" << endl;
		return FALSE;
	}

	hprocess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hprocess == NULL)
	{
		cout << "ERROR : There is no access to terminate" << endl;
		return FALSE;
	}
	bret = TerminateProcess(hprocess, 0);
	if (bret == FALSE)
	{
		cout << "ERROR : Unable to terminate process";
		return FALSE;
	}
}

///////////////////////////////////////////////////////////////////////////////////
//Function name:	HardwareInfo
//Function date:	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		NONE
//Description:		This function displays all Process and hardware information
//Return value: 	Boolean
//Returns TRUE if all information is displayed successfully
//Else Returns FALSE if any error
////////////////////////////////////////////////////////////////////////////////////
BOOL HardwareInfo()
{
	SYSTEM_INFO siSysInfo;

	GetSystemInfo(&siSysInfo);

	cout << "OEM ID: " << siSysInfo.dwOemId << endl;
	cout << "Number of processors:" << siSysInfo.dwNumberOfProcessors << endl;
	cout << "Page size: " << siSysInfo.dwPageSize << endl;
	cout << "Processor type: " << siSysInfo.dwProcessorType << endl;
	cout << "Minimum application address:" << siSysInfo.lpMinimumApplicationAddress << endl;
	cout << "Maximum application address:" << siSysInfo.lpMaximumApplicationAddress << endl;
	cout << "Active processor mask: " << siSysInfo.dwActiveProcessorMask << endl;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
//Function name: 	DisplayHelp
//Function date:	26/11/2019
//Function Author:	Shweta Bhilare
//Parameters:		NONE
//Description:		This function provides help about the different functions used in this project 
//Return value: 	Void
///////////////////////////////////////////////////////////////////////////////////////////////////////
void DisplayHelp()
{
	cout << "Developed by Marvellous Infosystems" << endl;
	cout << "ps : Display all information of process" << endl;
	cout << "ps -t : Display all information about threads" << endl;
	cout << "ps -d :Display all information about DLL" << endl;
	cout << "cls : Clear the contents on console" << endl;
	cout << "log : Creates log of current running process on C drive" << endl;
	cout << "readlog : Display the information from specified log file" << endl;
	cout << "sysinfo : Display the current hardware configuration" << endl;
	cout << "search : Search and display information of specific running process" << endl;
	cout << "exit : Terminate Marvellous ProcMon" << endl;
}


//main function
int main(int argc, char* argv[])
{
	BOOL bret;
	char* ptr = NULL;
	ProcessInfo* ppobj = NULL;
	char command[4][80], str[80];
	int count, min, date, month, hr;

	while (1)
	{
		fflush(stdin);
		strcpy_s(str, "");

		string ch = "-a";
		cout << endl << "Marvellous ProcMon : > ";
		fgets(str, 80, stdin);

		count = sscanf(str, "%s %s %s %s", command[0], command[1], command[2], command[3]);

		if (count == 1)
		{
			if (_stricmp(command[0], "ps") == 0)
			{
				
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessDisplay(ch);
				if (bret == FALSE)
					cout << "ERROR : Unable to display process" << endl;
				delete ppobj;
			}
			else if (_stricmp(command[0], "log") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessLog();
				if (bret == FALSE)
					cout << "ERROR : Unable to create log file" << endl;
				delete ppobj;
			}
			else if (_stricmp(command[0], "sysinfo") == 0)
			{
				bret = HardwareInfo();
				if (bret == FALSE)
					cout << "ERROR : Unable to get hardware informatio" << endl;
				cout << "Hardware information of current system is :" << endl;

			}
			else if (_stricmp(command[0], "readlog") == 0)
			{
				ProcessInfo* ppobj;
				ppobj = new ProcessInfo();
				cout << "Enter log file details as :" << endl;
				cout << "Hour : "; cin >> hr;
				cout << endl << "Minute : "; cin >> min;
				cout << endl << "Date : "; cin >> date;
				cout << endl << "Month : "; cin >> month;

				bret = ppobj->ReadLog(hr, min, date, month);

				if (bret == FALSE)
					cout << "ERROR : Unable to read specified log file" << endl;
				delete ppobj;
			}
			else if (_stricmp(command[0], "clear") == 0)
			{
				system("cls");
				continue;
			}
			else if (_stricmp(command[0], "help") == 0)
			{
				DisplayHelp();
				continue;
			}
			else if (_stricmp(command[0], "exit") == 0)
			{
				cout << endl << "Terminating the Marvellous ProcMon" << endl;
				break;
			}
			else
			{
				cout << endl << "ERROR : Command not found !!" << endl;
				continue;
			}
		}
		else if (count == 2)
		{
			if (_stricmp(command[0], "ps") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessDisplay(command[1]);

				if (bret == FALSE)
					cout << "ERROR :Unable to display process information" << endl;
				delete ppobj;
			}
			else if (_stricmp(command[0], "search") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessSearch(command[1]);
				if (bret == FALSE)
					cout << "ERROR : There is no such process" << endl;
				delete ppobj;
				continue;
			}
			else if (_stricmp(command[0], "kill") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->KillProcess(command[1]);

				if (bret == FALSE)
					cout << "ERROR : There is no such process" << endl;
				else
					cout << command[1] << "Terminated succesfully" << endl;
				delete ppobj;
				continue;
			}
		}
		else
		{
			cout << endl << "ERROR : Command not found !!!" << endl;
			continue;
		}
	}
	return 0;
}
