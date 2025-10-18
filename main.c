#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

typedef struct {
    WCHAR name[MAX_PATH];
    int distance;
} ProcessSuggestion;

typedef struct {
    DWORD pid;
    DWORD parentPid;
    DWORD threadCount;
    LONG basePriority;
    WCHAR name[MAX_PATH];
    WCHAR parentName[MAX_PATH];
} ProcessInfo;

typedef struct {
    DWORD tid;
    DWORD ownerPid;
    LONG basePriority;
    LONG deltaPriority;
} ThreadInfo;

void PrintBanner() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    FILE* banner = _wfopen(L"banner.txt", L"rb");
    if (!banner)
        return;

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), banner)) {
        printf("%s", buffer);
    }
    fclose(banner);
}

void PrintHelp(LPWSTR progName) {
    wprintf(L"\nusage: %s [options] <argument>\n\n", progName);
    wprintf(L"options:\n");
    wprintf(L"  -i, --inspect <process_name>    inspect process and display information\n");
    wprintf(L"  -m, --modules <process_name>    list loaded modules (dlls)\n");
    wprintf(L"  -t, --threads <process_name>    list all threads\n");
    wprintf(L"  -l, --list                      list all running processes\n");
    wprintf(L"  -h, --help                      display this help message\n\n");
    wprintf(L"examples:\n");
    wprintf(L"  %s -i notepad.exe\n", progName);
    wprintf(L"  %s -m chrome.exe\n", progName);
    wprintf(L"  %s -t discord.exe\n", progName);
    wprintf(L"  %s --list\n\n", progName);
}

int LevenshteinDistance(LPCWSTR s1, LPCWSTR s2) {
    int len1 = lstrlenW(s1);
    int len2 = lstrlenW(s2);
    int* prev = (int*)malloc((len2 + 1) * sizeof(int));
    int* curr = (int*)malloc((len2 + 1) * sizeof(int));

    for (int j = 0; j <= len2; j++) prev[j] = j;

    for (int i = 1; i <= len1; i++) {
        curr[0] = i;
        for (int j = 1; j <= len2; j++) {
            int cost = (towlower(s1[i - 1]) == towlower(s2[j - 1])) ? 0 : 1;
            curr[j] = min(min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
        }
        int* temp = prev;
        prev = curr;
        curr = temp;
    }

    int result = prev[len2];
    free(prev);
    free(curr);
    return result;
}

BOOL ContainsSubstring(LPCWSTR haystack, LPCWSTR needle) {
    WCHAR lowerHaystack[MAX_PATH * 2] = { 0 };
    WCHAR lowerNeedle[MAX_PATH * 2] = { 0 };

    for (DWORD i = 0; i < lstrlenW(haystack) && i < MAX_PATH * 2 - 1; i++)
        lowerHaystack[i] = towlower(haystack[i]);
    for (DWORD i = 0; i < lstrlenW(needle) && i < MAX_PATH * 2 - 1; i++)
        lowerNeedle[i] = towlower(needle[i]);

    return wcsstr(lowerHaystack, lowerNeedle) != NULL;
}

int CompareSuggestions(const void* a, const void* b) {
    return ((ProcessSuggestion*)a)->distance - ((ProcessSuggestion*)b)->distance;
}

BOOL GetAllProcessInfo(ProcessInfo** outProcesses, DWORD* outCount) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    DWORD count = 0;
    PROCESSENTRY32 pe32 = { .dwSize = sizeof(PROCESSENTRY32) };
    if (Process32First(hSnapshot, &pe32)) {
        do { count++; } while (Process32Next(hSnapshot, &pe32));
    }

    ProcessInfo* processes = (ProcessInfo*)malloc(count * sizeof(ProcessInfo));
    if (!processes) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    DWORD index = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            processes[index].pid = pe32.th32ProcessID;
            processes[index].parentPid = pe32.th32ParentProcessID;
            processes[index].threadCount = pe32.cntThreads;
            processes[index].basePriority = pe32.pcPriClassBase;
            wcscpy_s(processes[index].name, MAX_PATH, pe32.szExeFile);
            processes[index].parentName[0] = L'\0';
            index++;
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    for (DWORD i = 0; i < count; i++) {
        for (DWORD j = 0; j < count; j++) {
            if (processes[i].parentPid == processes[j].pid) {
                wcscpy_s(processes[i].parentName, MAX_PATH, processes[j].name);
                break;
            }
        }
        if (processes[i].parentName[0] == L'\0') {
            wcscpy_s(processes[i].parentName, MAX_PATH, L"unknown");
        }
    }

    *outProcesses = processes;
    *outCount = count;
    return TRUE;
}

BOOL GetAllThreadInfo(ThreadInfo** outThreads, DWORD* outCount) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    DWORD count = 0;
    THREADENTRY32 te32 = { .dwSize = sizeof(THREADENTRY32) };
    if (Thread32First(hSnapshot, &te32)) {
        do { count++; } while (Thread32Next(hSnapshot, &te32));
    }

    ThreadInfo* threads = (ThreadInfo*)malloc(count * sizeof(ThreadInfo));
    if (!threads) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    DWORD index = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            threads[index].tid = te32.th32ThreadID;
            threads[index].ownerPid = te32.th32OwnerProcessID;
            threads[index].basePriority = te32.tpBasePri;
            threads[index].deltaPriority = te32.tpDeltaPri;
            index++;
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    *outThreads = threads;
    *outCount = count;
    return TRUE;
}

ProcessInfo* FindProcessInfo(ProcessInfo* processes, DWORD count, DWORD pid) {
    for (DWORD i = 0; i < count; i++) {
        if (processes[i].pid == pid) return &processes[i];
    }
    return NULL;
}

void FindSimilarProcesses(LPWSTR searchName, ProcessSuggestion* suggestions, int* count, int maxSuggestions) {
    ProcessInfo* allProcesses = NULL;
    DWORD processCount = 0;

    if (!GetAllProcessInfo(&allProcesses, &processCount)) return;

    *count = 0;
    for (DWORD i = 0; i < processCount && *count < maxSuggestions; i++) {
        BOOL exists = FALSE;
        for (int j = 0; j < *count; j++) {
            if (wcscmp(suggestions[j].name, allProcesses[i].name) == 0) {
                exists = TRUE;
                break;
            }
        }

        if (!exists) {
            int distance = LevenshteinDistance(searchName, allProcesses[i].name);
            BOOL contains = ContainsSubstring(allProcesses[i].name, searchName);

            if (contains || distance <= 5) {
                if (contains) distance -= 3;
                wcscpy_s(suggestions[*count].name, MAX_PATH, allProcesses[i].name);
                suggestions[*count].distance = distance;
                (*count)++;
            }
        }
    }

    free(allProcesses);
    qsort(suggestions, *count, sizeof(ProcessSuggestion), CompareSuggestions);
}

BOOL ProcEnum(LPWSTR szProcessName, DWORD* dwProcId, HANDLE* hProcess) {
    *dwProcId = 0;
    *hProcess = NULL;

    ProcessInfo* allProcesses = NULL;
    DWORD processCount = 0;

    if (!GetAllProcessInfo(&allProcesses, &processCount)) {
        wprintf(L"failed to get process info\n");
        return FALSE;
    }

    WCHAR LowerSearchName[MAX_PATH * 2] = { 0 };
    DWORD searchLen = lstrlenW(szProcessName);
    if (searchLen < MAX_PATH * 2) {
        for (DWORD i = 0; i < searchLen; i++)
            LowerSearchName[i] = (WCHAR)towlower(szProcessName[i]);
        LowerSearchName[searchLen] = L'\0';
    }

    for (DWORD i = 0; i < processCount; i++) {
        WCHAR LowerName[MAX_PATH * 2] = { 0 };
        DWORD dwSize = lstrlenW(allProcesses[i].name);
        if (dwSize < MAX_PATH * 2) {
            for (DWORD j = 0; j < dwSize; j++)
                LowerName[j] = (WCHAR)towlower(allProcesses[i].name[j]);
            LowerName[dwSize] = L'\0';
        }

        if (wcscmp(LowerName, LowerSearchName) == 0) {
            *dwProcId = allProcesses[i].pid;
            *hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, allProcesses[i].pid);
            break;
        }
    }

    free(allProcesses);
    return *dwProcId != 0;
}

void ListModules(LPWSTR processName) {
    DWORD dwProcId = 0;
    HANDLE hProcess = NULL;

    if (!ProcEnum(processName, &dwProcId, &hProcess)) {
        wprintf(L"\nprocess '%s' not found\n\n", processName);
        return;
    }

    wprintf(L"\nmodules loaded in %ls (pid: %lu)\n", processName, dwProcId);
    wprintf(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < moduleCount; i++) {
            WCHAR szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    wprintf(L"[0x%p] %ls (%lu kb)\n",
                        modInfo.lpBaseOfDll,
                        szModName,
                        modInfo.SizeOfImage / 1024);
                }
            }
        }
        wprintf(L"\ntotal: %lu modules\n", moduleCount);
    }

    CloseHandle(hProcess);
    wprintf(L"\n");
}

void ListThreads(LPWSTR processName) {
    DWORD dwProcId = 0;
    HANDLE hProcess = NULL;

    if (!ProcEnum(processName, &dwProcId, &hProcess)) {
        wprintf(L"\nprocess '%s' not found\n\n", processName);
        return;
    }

    ThreadInfo* allThreads = NULL;
    DWORD threadCount = 0;

    if (!GetAllThreadInfo(&allThreads, &threadCount)) {
        wprintf(L"failed to get thread info\n");
        CloseHandle(hProcess);
        return;
    }

    wprintf(L"\nthreads in %ls (pid: %lu)\n", processName, dwProcId);
    wprintf(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    DWORD count = 0;
    for (DWORD i = 0; i < threadCount; i++) {
        if (allThreads[i].ownerPid == dwProcId) {
            wprintf(L"tid: %-8lu  base priority: %-3ld  delta priority: %ld\n",
                allThreads[i].tid,
                allThreads[i].basePriority,
                allThreads[i].deltaPriority);
            count++;
        }
    }

    wprintf(L"\ntotal: %lu threads\n\n", count);

    free(allThreads);
    CloseHandle(hProcess);
}

void ListAllProcesses() {
    ProcessInfo* allProcesses = NULL;
    DWORD processCount = 0;

    if (!GetAllProcessInfo(&allProcesses, &processCount)) {
        wprintf(L"failed to get process info\n");
        return;
    }

    wprintf(L"\nrunning processes\n");
    wprintf(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    wprintf(L"%-8s  %-8s  %-40s\n", L"pid", L"threads", L"name");

    for (DWORD i = 0; i < processCount; i++) {
        wprintf(L"%-8lu  %-8lu  %ls\n",
            allProcesses[i].pid,
            allProcesses[i].threadCount,
            allProcesses[i].name);
    }

    wprintf(L"\ntotal: %lu processes\n\n", processCount);
    free(allProcesses);
}

void InspectProc(LPWSTR processName) {
    DWORD dwProcId = 0;
    HANDLE hProcess = NULL;

    if (!ProcEnum(processName, &dwProcId, &hProcess)) {
        wprintf(L"\nprocess '%s' not found\n\n", processName);

        ProcessSuggestion suggestions[10];
        int suggestionCount = 0;
        FindSimilarProcesses(processName, suggestions, &suggestionCount, 10);

        if (suggestionCount > 0) {
            wprintf(L"did you mean:\n");
            for (int i = 0; i < suggestionCount && i < 5; i++)
                wprintf(L"  - %s\n", suggestions[i].name);
        }
        return;
    }

    ProcessInfo* allProcesses = NULL;
    DWORD processCount = 0;
    GetAllProcessInfo(&allProcesses, &processCount);

    ProcessInfo* procInfo = FindProcessInfo(allProcesses, processCount, dwProcId);

    wprintf(L"\n%ls\n", processName);
    wprintf(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    wprintf(L"basic\n");
    wprintf(L"  pid                    %lu\n", dwProcId);

    if (procInfo) {
        wprintf(L"  parent pid             %lu (%ls)\n", procInfo->parentPid, procInfo->parentName);
        wprintf(L"  base priority          %ld\n", procInfo->basePriority);
        wprintf(L"  threads                %lu\n", procInfo->threadCount);
    }

    if (hProcess) {
        BOOL isElevated = FALSE;
        HANDLE hToken = NULL;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                isElevated = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
        wprintf(L"  elevated               %ls\n", isElevated ? L"yes" : L"no");

        DWORD sessionId = 0;
        if (ProcessIdToSessionId(dwProcId, &sessionId)) {
            wprintf(L"  session id             %lu\n", sessionId);
        }

        wprintf(L"\nmemory\n");
        PROCESS_MEMORY_COUNTERS_EX pmcEx = { 0 };
        pmcEx.cb = sizeof(pmcEx);
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmcEx, sizeof(pmcEx))) {
            wprintf(L"  working set            %llu kb\n", (unsigned long long)(pmcEx.WorkingSetSize / 1024));
            wprintf(L"  peak working set       %llu kb\n", (unsigned long long)(pmcEx.PeakWorkingSetSize / 1024));
            wprintf(L"  private bytes          %llu kb\n", (unsigned long long)(pmcEx.PrivateUsage / 1024));
            wprintf(L"  pagefile usage         %llu kb\n", (unsigned long long)(pmcEx.PagefileUsage / 1024));
            wprintf(L"  peak pagefile          %llu kb\n", (unsigned long long)(pmcEx.PeakPagefileUsage / 1024));
            wprintf(L"  page faults            %lu\n", pmcEx.PageFaultCount);
        }

        wprintf(L"\ni/o counters\n");
        IO_COUNTERS ioCounters = { 0 };
        if (GetProcessIoCounters(hProcess, &ioCounters)) {
            wprintf(L"  read operations        %llu\n", ioCounters.ReadOperationCount);
            wprintf(L"  write operations       %llu\n", ioCounters.WriteOperationCount);
            wprintf(L"  other operations       %llu\n", ioCounters.OtherOperationCount);
            wprintf(L"  read bytes             %llu kb\n", ioCounters.ReadTransferCount / 1024);
            wprintf(L"  write bytes            %llu kb\n", ioCounters.WriteTransferCount / 1024);
            wprintf(L"  other bytes            %llu kb\n", ioCounters.OtherTransferCount / 1024);
        }

        wprintf(L"\nhandles\n");
        DWORD handleCount = 0;
        if (GetProcessHandleCount(hProcess, &handleCount)) {
            wprintf(L"  handle count           %lu\n", handleCount);
        }

        DWORD gdiObjects = GetGuiResources(hProcess, GR_GDIOBJECTS);
        DWORD userObjects = GetGuiResources(hProcess, GR_USEROBJECTS);
        if (gdiObjects || userObjects) {
            wprintf(L"  gdi objects            %lu\n", gdiObjects);
            wprintf(L"  user objects           %lu\n", userObjects);
        }

        wprintf(L"\npriority\n");
        DWORD priorityClass = GetPriorityClass(hProcess);
        wprintf(L"  priority class         ");
        switch (priorityClass) {
        case IDLE_PRIORITY_CLASS: wprintf(L"idle\n"); break;
        case BELOW_NORMAL_PRIORITY_CLASS: wprintf(L"below normal\n"); break;
        case NORMAL_PRIORITY_CLASS: wprintf(L"normal\n"); break;
        case ABOVE_NORMAL_PRIORITY_CLASS: wprintf(L"above normal\n"); break;
        case HIGH_PRIORITY_CLASS: wprintf(L"high\n"); break;
        case REALTIME_PRIORITY_CLASS: wprintf(L"realtime\n"); break;
        default: wprintf(L"unknown\n"); break;
        }

        DWORD depFlags = 0;
        BOOL depPermanent = FALSE;
        if (GetProcessDEPPolicy(hProcess, &depFlags, &depPermanent)) {
            wprintf(L"  dep enabled            %ls%ls\n",
                (depFlags & PROCESS_DEP_ENABLE) ? L"yes" : L"no",
                depPermanent ? L" (permanent)" : L"");
        }

        wprintf(L"\npath\n");
        WCHAR exePath[MAX_PATH * 2] = { 0 };
        DWORD pathLen = MAX_PATH * 2;
        if (QueryFullProcessImageNameW(hProcess, 0, exePath, &pathLen)) {
            wprintf(L"  executable             %ls\n", exePath);

            WIN32_FILE_ATTRIBUTE_DATA fileData;
            if (GetFileAttributesExW(exePath, GetFileExInfoStandard, &fileData)) {
                ULARGE_INTEGER fileSize;
                fileSize.LowPart = fileData.nFileSizeLow;
                fileSize.HighPart = fileData.nFileSizeHigh;
                wprintf(L"  file size              %llu kb\n", fileSize.QuadPart / 1024);
            }
        }
        CloseHandle(hProcess);
    }

    if (allProcesses) free(allProcesses);
    wprintf(L"\n");
}

int wmain(int argc, LPWSTR argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintHelp(argv[0]);
        return -1;
    }

    if (wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"--help") == 0)
        PrintHelp(argv[0]);
    else if (wcscmp(argv[1], L"-i") == 0 || wcscmp(argv[1], L"--inspect") == 0) {
        if (argc < 3) {
            wprintf(L"\ninspect flag requires a process name\n");
            return -1;
        }
        InspectProc(argv[2]);
    }
    else if (wcscmp(argv[1], L"-m") == 0 || wcscmp(argv[1], L"--modules") == 0) {
        if (argc < 3) {
            wprintf(L"\nmodules flag requires a process name\n");
            return -1;
        }
        ListModules(argv[2]);
    }
    else if (wcscmp(argv[1], L"-t") == 0 || wcscmp(argv[1], L"--threads") == 0) {
        if (argc < 3) {
            wprintf(L"\nthreads flag requires a process name\n");
            return -1;
        }
        ListThreads(argv[2]);
    }
    else if (wcscmp(argv[1], L"-l") == 0 || wcscmp(argv[1], L"--list") == 0) {
        ListAllProcesses();
    }
    else {
        wprintf(L"\nunknown option: %ls\n", argv[1]);
        wprintf(L"try '%s --help' for more information\n\n", argv[0]);
        return -1;
    }

    return 0;
}