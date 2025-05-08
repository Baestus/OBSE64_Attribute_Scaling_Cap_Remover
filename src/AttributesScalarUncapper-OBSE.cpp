// dllmain.cpp for StrengthCapUncapper
#include "pch.h" // Precompiled header (ensure it's used or remove if not)
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <cstdio>       // For sprintf_s

#include <Psapi.h>      // For GetModuleInformation
#include <obse64/PluginAPI.h> // OBSE header

#include "PatternScanner.h" // Your common PatternScanner

#pragma comment(lib, "Psapi.lib")

// --- Plugin Configuration ---
#define ENABLE_DEBUG_LOGGING 0 // Set to 1 to enable detailed AOB parsing/scanning logs, 0 for release
const char* PLUGIN_NAME_STR = "Attribute Scalar Cap Uncapper";
const unsigned int PLUGIN_VERSION_MAJOR = 1;
const unsigned int PLUGIN_VERSION_MINOR = 3;
const char* AUTHOR_NAME = "jab" ; // << SET THIS

// --- Logging Prefix ---
static std::string LOG_PREFIX_STR; // Initialized in OBSEPlugin_Load

// --- Global Variables ---
PluginHandle g_pluginHandle = kPluginHandle_Invalid;
HMODULE      g_GameHandle = nullptr;
uintptr_t    g_GameBaseAddr = 0;
size_t       g_GameModuleSize = 0;

// --- AOB Patterns and Patch Details ---
// Hand-to-Hand Strength Cap (targets a CMOV instruction, e.g., 0F 4F D8)
const char* H2H_STRENGTH_CAP_AOB = "C7 44 24 ?? 00 00 80 3F F3 0F 10 1D ?? ?? ?? ?? 0F 4F D8 0F 28 C3 48 8D 44 24 ??";
constexpr size_t H2H_PATCH_OFFSET_IN_PATTERN = 16; // Offset from start of H2H_AOB to the CMOV
constexpr std::array<uint8_t, 3> H2H_PATCH_BYTES = { 0x90, 0x90, 0x90 }; // NOP, NOP, NOP (3 bytes)

// Weapon Strength Cap (targets a CMOV instruction)
const char* WEAPON_STRENGTH_CAP_AOB = "B8 64 00 00 00 0F 57 C9 3B D8 0F 28 F0 0F 4F D8 F3 0F 2A CB F3 0F 59 F1";
constexpr size_t WEAPON_PATCH_OFFSET_IN_PATTERN = 13; // Offset from start of WEAPON_AOB to the CMOV
constexpr std::array<uint8_t, 3> WEAPON_PATCH_BYTES = { 0x90, 0x90, 0x90 }; // NOP, NOP, NOP (3 bytes)

// --- Helper Function: Apply a single patch ---
template<size_t N> // Template to handle different patch byte array sizes if needed
bool ApplyPatch(const char* patchName, uintptr_t baseAddressToSearch, size_t searchRegionSize,
    const char* patternAOB, size_t patchOffsetInPattern,
    const std::array<uint8_t, N>& patchBytes)
{
    char logBuffer[512];
    std::vector<uint8_t> pattern_vec_bytes;
    std::vector<bool> pattern_vec_mask;

#if ENABLE_DEBUG_LOGGING
    sprintf_s(logBuffer, sizeof(logBuffer), "%sParsing %s AOB: %s", LOG_PREFIX_STR.c_str(), patchName, patternAOB);
    OutputDebugStringA(logBuffer);
#endif
    if (!PatternScan::ParseAOBString(patternAOB, pattern_vec_bytes, pattern_vec_mask)) {
        sprintf_s(logBuffer, sizeof(logBuffer), "%sERROR - Failed to parse %s AOB string!", LOG_PREFIX_STR.c_str(), patchName);
        OutputDebugStringA(logBuffer);
        return false;
    }

#if ENABLE_DEBUG_LOGGING
    sprintf_s(logBuffer, sizeof(logBuffer), "%sScanning for %s pattern...", LOG_PREFIX_STR.c_str(), patchName);
    OutputDebugStringA(logBuffer);
#endif
    uintptr_t foundPatternAddr = PatternScan::FindPattern(baseAddressToSearch, searchRegionSize, pattern_vec_bytes, pattern_vec_mask);

    if (foundPatternAddr == 0) {
        sprintf_s(logBuffer, sizeof(logBuffer), "%sERROR - %s pattern NOT FOUND! AOB needs update for current game version.", LOG_PREFIX_STR.c_str(), patchName);
        OutputDebugStringA(logBuffer);
        return false;
    }
#if ENABLE_DEBUG_LOGGING
    sprintf_s(logBuffer, sizeof(logBuffer), "%sFound %s pattern at 0x%p", LOG_PREFIX_STR.c_str(), patchName, (void*)foundPatternAddr);
    OutputDebugStringA(logBuffer);
#endif

    uintptr_t targetPatchAddress = foundPatternAddr + patchOffsetInPattern;
#if ENABLE_DEBUG_LOGGING
    sprintf_s(logBuffer, sizeof(logBuffer), "%sCalculated %s target patch address: 0x%p", LOG_PREFIX_STR.c_str(), patchName, (void*)targetPatchAddress);
    OutputDebugStringA(logBuffer);
#endif

    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(targetPatchAddress), patchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        sprintf_s(logBuffer, sizeof(logBuffer), "%sERROR - VirtualProtect (RWX) failed for %s patch at 0x%p. Error: %lu",
            LOG_PREFIX_STR.c_str(), patchName, (void*)targetPatchAddress, GetLastError());
        OutputDebugStringA(logBuffer);
        return false;
    }

    memcpy(reinterpret_cast<void*>(targetPatchAddress), patchBytes.data(), patchBytes.size());
    sprintf_s(logBuffer, sizeof(logBuffer), "%sApplied %s patch at 0x%p.", LOG_PREFIX_STR.c_str(), patchName, (void*)targetPatchAddress);
    OutputDebugStringA(logBuffer);

    DWORD dummyProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(targetPatchAddress), patchBytes.size(), oldProtect, &dummyProtect)) {
        sprintf_s(logBuffer, sizeof(logBuffer), "%sWARNING - VirtualProtect restore failed for %s patch at 0x%p. Error: %lu",
            LOG_PREFIX_STR.c_str(), patchName, (void*)targetPatchAddress, GetLastError());
        OutputDebugStringA(logBuffer); // Non-fatal warning
    }
    return true;
}

// --- Core Mod Initialization ---
bool InitializeMod() {
    OutputDebugStringA((LOG_PREFIX_STR + "Initializing...\n").c_str());

    g_GameHandle = GetModuleHandleA(NULL);
    if (!g_GameHandle) {
        OutputDebugStringA((LOG_PREFIX_STR + "Failed to get game module handle.\n").c_str());
        return false;
    }
    g_GameBaseAddr = reinterpret_cast<uintptr_t>(g_GameHandle);

    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), g_GameHandle, &modInfo, sizeof(MODULEINFO))) {
        OutputDebugStringA((LOG_PREFIX_STR + "Failed to get module information.\n").c_str());
        return false;
    }
    g_GameModuleSize = modInfo.SizeOfImage;

#if ENABLE_DEBUG_LOGGING
    char logBuffer[256];
    sprintf_s(logBuffer, sizeof(logBuffer), "%sGame Base: 0x%p, Size: 0x%IX", LOG_PREFIX_STR.c_str(), (void*)g_GameBaseAddr, g_GameModuleSize);
    OutputDebugStringA(logBuffer);
#endif

    if (!ApplyPatch("H2H Strength Cap", g_GameBaseAddr, g_GameModuleSize,
        H2H_STRENGTH_CAP_AOB, H2H_PATCH_OFFSET_IN_PATTERN, H2H_PATCH_BYTES)) {
        return false;
    }

    if (!ApplyPatch("Weapon Strength Cap", g_GameBaseAddr, g_GameModuleSize,
        WEAPON_STRENGTH_CAP_AOB, WEAPON_PATCH_OFFSET_IN_PATTERN, WEAPON_PATCH_BYTES)) {
        return false;
    }

    OutputDebugStringA((LOG_PREFIX_STR + "Initialization successful.\n").c_str());
    return true;
}

// --- Core Mod Cleanup ---
void CleanupMod() {
    OutputDebugStringA((LOG_PREFIX_STR + "Cleaning up (no specific actions for patches).\n").c_str());
    // Patches are not reverted. No dynamic resources to free here.
}

// --- OBSE Plugin Exports ---
extern "C" {
    __declspec(dllexport) OBSEPluginVersionData OBSEPlugin_Version = {
        OBSEPluginVersionData::kVersion,
        2, // Plugin version
        "Attribute Scalar Uncapper",
        "jab", // Author
        OBSEPluginVersionData::kAddressIndependence_Signatures,
        OBSEPluginVersionData::kStructureIndependence_NoStructs,
        {0}, // Compatible Oblivion.exe version (usually { RUNTIME_VERSION_1_2_416, 0 } or left {0} for any)
        0,   // OBSE major version requirement (0 for any)
        0, 0, {0} // Reserved
    };

    __declspec(dllexport) bool OBSEPlugin_Load(const OBSEInterface* obse) {
        g_pluginHandle = obse->GetPluginHandle();

        // Construct log prefix string
        char versionStr[16];
        sprintf_s(versionStr, sizeof(versionStr), "v%u.%u", PLUGIN_VERSION_MAJOR, PLUGIN_VERSION_MINOR);
        LOG_PREFIX_STR = std::string(PLUGIN_NAME_STR) + " " + versionStr + ": ";

        // Optional: Query OBSE interfaces if needed for more advanced features
        // if (obse->isEditor) { /* Don't run in CS */ return true; }
        // if (obse->obseVersion < MIN_OBSE_VERSION_REQUIRED) { /* Error */ return false; }

        if (!InitializeMod()) {
            OutputDebugStringA((LOG_PREFIX_STR + "Failed to initialize. Plugin will not be active.\n").c_str());
            // Optionally, use OBSE's _MESSAGE functionality to inform the user in-game.
            return false; // Signal OBSE that plugin loading failed
        }
        return true; // Signal OBSE that plugin loaded successfully
    }
} // End extern "C"

// --- Standard DllMain ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        // Initialization is deferred to OBSEPlugin_Load
        break;
    case DLL_PROCESS_DETACH:
        CleanupMod();
        break;
    }
    return TRUE;
}