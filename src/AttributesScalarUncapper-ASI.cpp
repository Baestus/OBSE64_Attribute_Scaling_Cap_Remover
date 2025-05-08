#include "pch.h"       // Or remove if not using precompiled headers
#include <windows.h>
#include <cstdint>
#include <vector>       // Added for std::vector
#include <string>       // Added for std::string
#include <sstream>      // Added for std::istringstream
#include <iomanip>      // Added for std::hex
#include <cctype>       // Added for std::isxdigit, std::isspace
#include <algorithm>    // Added for std::remove_if
#include <array>
#include <memoryapi.h>  // For VirtualProtect
#include <psapi.h>      // Added for GetModuleInformatio

// --- Logging Control ---
// Set to true to enable debug logging, set to false to disable it.
constexpr bool g_EnableLogging = false; // <--- CHANGE THIS TO false TO DISABLE LOGGING

// --- Global Variables ---
HMODULE g_DllHandle = nullptr;       // Handle to this DLL module
HMODULE g_GameHandle = nullptr;      // Handle to the game module (Oblivion.exe)
uintptr_t g_GameBaseAddr = 0;      // Base address of the game module
size_t    g_GameModuleSize = 0;

const char* H2H_STRENGTH_CAP_AOB = "C7 44 24 ?? 00 00 80 3F F3 0F 10 1D ?? ?? ?? ?? 0F 4F D8 0F 28 C3 48 8D 44 24 ??"; // e.g., "7C ?? 0F 4D ?? ?? ?? 8B ?? 48 8B"
const char* WEAPON_STRENGTH_CAP_AOB = "B8 64 00 00 00 0F 57 C9 3B D8 0F 28 F0 0F 4F D8 F3 0F 2A CB F3 0F 59 F1"; // e.g., "F3 0F ?? ?? 0F 4D ?? ?? ?? 8B ?? 48"

// --- AOB Patch Details ---
// Offset *within* the found H2H pattern where the patch should start.
// If your AOB starts exactly at the CMOV, this is 0.
constexpr size_t H2H_PATCH_OFFSET_IN_PATTERN = 16; // Offset to the H2H '0F 4F D8'
constexpr size_t H2H_PATCH_SIZE = 3; // Size of the CMOV instruction
constexpr std::array<std::uint8_t, H2H_PATCH_SIZE> H2H_PATCH_BYTES = { 0x90, 0x90, 0x90 }; // NOPs

// Offset *within* the found Weapon pattern where the patch should start.
constexpr size_t WEAPON_PATCH_OFFSET_IN_PATTERN = 13; // Offset to the Weapon '0F 4F D8'
constexpr size_t WEAPON_PATCH_SIZE = 3; // Size of the CMOV instruction
constexpr std::array<std::uint8_t, WEAPON_PATCH_SIZE> WEAPON_PATCH_BYTES = { 0x90, 0x90, 0x90 }; // NOPs

// Helper function to format address as hex string (e.g., 0x00007FF...)
std::string FormatAddress(uintptr_t address) {
    std::stringstream ss;
    // Output "0x" prefix, set fill to '0', set width based on pointer size (16 for 64-bit), format as hex
    ss << "0x" << std::hex << std::setfill('0') << std::setw(sizeof(uintptr_t) * 2) << address;
    return ss.str();
}

// --- AOB Scanning Utilities ---

// Simple logging helper (outputs to Debug Output window)
void LogDebug(const std::string& message) {
    // Only proceed if logging is enabled
    if (!g_EnableLogging) {
        return; // Do nothing if logging is disabled
    }
    OutputDebugStringA(("StrengthCapFixASI: " + message + "\n").c_str());
}

// Parses an AOB string (e.g., "48 89 ?? 5C") into bytes and a mask.
// Wildcards ("??") are marked in the mask.
bool ParseAOBString(const std::string& aob_str, std::vector<uint8_t>& out_bytes, std::vector<bool>& out_mask)
{
    out_bytes.clear();
    out_mask.clear();
    std::string current_byte_str;
    std::istringstream iss(aob_str);
    std::string token;

    while (iss >> token)
    {
        if (token == "?" || token == "??")
        {
            out_bytes.push_back(0x00); // Placeholder byte
            out_mask.push_back(true);  // Mark as wildcard
        }
        else if (token.length() == 2 &&
            std::isxdigit(static_cast<unsigned char>(token[0])) &&
            std::isxdigit(static_cast<unsigned char>(token[1])))
        {
            try {
                out_bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
                out_mask.push_back(false); // Not a wildcard
            }
            catch (const std::exception& e) {
                LogDebug("Error parsing AOB token '" + token + "': " + e.what());
                return false; // Parsing error
            }
        }
        else
        {
            LogDebug("Invalid AOB token encountered: '" + token + "'");
            return false; // Invalid token format
        }
    }

    return !out_bytes.empty(); // Success if we parsed at least one byte/wildcard
}

// Finds a pattern (bytes with mask) within a memory region.
uintptr_t FindPattern(uintptr_t start_address, size_t region_size, const std::vector<uint8_t>& pattern_bytes, const std::vector<bool>& pattern_mask)
{
    if (pattern_bytes.empty() || pattern_bytes.size() != pattern_mask.size() || region_size < pattern_bytes.size()) {
        LogDebug("FindPattern: Invalid input or region too small.");
        return 0; // Invalid input or impossible to find
    }

    const size_t pattern_size = pattern_bytes.size();
    const uint8_t* scan_start = reinterpret_cast<const uint8_t*>(start_address);
    const uint8_t* scan_end = scan_start + region_size - pattern_size;

    for (const uint8_t* current_addr = scan_start; current_addr <= scan_end; ++current_addr)
    {
        bool found = true;
        for (size_t i = 0; i < pattern_size; ++i)
        {
            // If it's not a wildcard and the bytes don't match, this isn't the spot
            if (!pattern_mask[i] && current_addr[i] != pattern_bytes[i])
            {
                found = false;
                break;
            }
        }

        if (found) {
            return reinterpret_cast<uintptr_t>(current_addr); // Found it!
        }
    }

    return 0; // Pattern not found
}

// --- Memory Patching Function ---
// Applies byte patches using the *found* addresses.
bool ApplyStrengthPatches(uintptr_t h2hPatternAddr, uintptr_t weaponPatternAddr)
{
    if (h2hPatternAddr == 0 || weaponPatternAddr == 0) {
        LogDebug("ApplyStrengthPatches: Cannot apply patches, one or both addresses are null.");
        return false; // Need valid addresses found by AOB scan
    }

    // Calculate the actual addresses to patch based on the pattern start and the offset
    uintptr_t h2hTargetAddress = h2hPatternAddr + H2H_PATCH_OFFSET_IN_PATTERN;
    uintptr_t weaponTargetAddress = weaponPatternAddr + WEAPON_PATCH_OFFSET_IN_PATTERN;

    LogDebug("Calculated H2H Patch Address: " + FormatAddress(h2hTargetAddress));
    LogDebug("Calculated Weapon Patch Address: " + FormatAddress(weaponTargetAddress));

    // --- Patch 1: Hand-to-Hand Strength Cap ---
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(h2hTargetAddress), H2H_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LogDebug("Failed to change memory protection for H2H patch at " + FormatAddress(h2hTargetAddress));
            return false;
        }
        memcpy(reinterpret_cast<void*>(h2hTargetAddress), H2H_PATCH_BYTES.data(), H2H_PATCH_SIZE);
        DWORD dummy = 0;
        VirtualProtect(reinterpret_cast<void*>(h2hTargetAddress), H2H_PATCH_SIZE, oldProtect, &dummy);
        LogDebug("Applied H2H patch successfully.");
    }

    // --- Patch 2: Weapon Strength Cap ---
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(weaponTargetAddress), WEAPON_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LogDebug("Failed to change memory protection for Weapon patch at 0x" + FormatAddress(h2hTargetAddress));
            // Consider if you want to revert the H2H patch here. For simplicity, just return false.
            return false;
        }
        memcpy(reinterpret_cast<void*>(weaponTargetAddress), WEAPON_PATCH_BYTES.data(), WEAPON_PATCH_SIZE);
        DWORD dummy = 0;
        VirtualProtect(reinterpret_cast<void*>(weaponTargetAddress), WEAPON_PATCH_SIZE, oldProtect, &dummy);
        LogDebug("Applied Weapon patch successfully.");
    }

    return true;
}


// --- Core Initialization Function ---
// Called from the initialization thread. Gets game address and applies patches.
bool InitializeMod()
{

    const char* potential_module_names[] = {
    "OblivionRemastered-Win64-Shipping.exe", // Add other potential names if needed (e.g., GDK version)
    "OblivionRemastered-WinGDK-Shipping.exe"
    };

    for (const char* name : potential_module_names) {
        g_GameHandle = GetModuleHandleA(name);
        if (g_GameHandle) {
            LogDebug("Found game module: " + std::string(name));
            break;
        }
    }

    if (!g_GameHandle) {
        LogDebug("Failed to get handle to the game module.");
        return false; // Cannot proceed without game handle
    }
    g_GameBaseAddr = reinterpret_cast<uintptr_t>(g_GameHandle);
    MODULEINFO moduleInfo = {};
    if (!GetModuleInformation(GetCurrentProcess(), g_GameHandle, &moduleInfo, sizeof(moduleInfo))) {
        LogDebug("Failed to get module information.");
        return false;
    }
    g_GameModuleSize = moduleInfo.SizeOfImage;

    LogDebug("Game Base Address: " + FormatAddress(g_GameBaseAddr));
    LogDebug("Game Module Size: " + std::to_string(g_GameModuleSize) + " bytes");


    // 2. Parse AOB Patterns
    std::vector<uint8_t> h2h_bytes, weapon_bytes;
    std::vector<bool> h2h_mask, weapon_mask;

    LogDebug("Parsing H2H AOB: " + std::string(H2H_STRENGTH_CAP_AOB));
    if (!ParseAOBString(H2H_STRENGTH_CAP_AOB, h2h_bytes, h2h_mask)) {
        LogDebug("Failed to parse H2H AOB pattern.");
        return false;
    }

    LogDebug("Parsing Weapon AOB: " + std::string(WEAPON_STRENGTH_CAP_AOB));
    if (!ParseAOBString(WEAPON_STRENGTH_CAP_AOB, weapon_bytes, weapon_mask)) {
        LogDebug("Failed to parse Weapon AOB pattern.");
        return false;
    }

    // 3. Scan for Patterns
    LogDebug("Scanning for H2H pattern...");
    uintptr_t h2h_found_addr = FindPattern(g_GameBaseAddr, g_GameModuleSize, h2h_bytes, h2h_mask);
    if (h2h_found_addr == 0) {
        LogDebug("H2H pattern not found!");
        // --- CRITICAL WARNING ---
        LogDebug("!!! H2H_STRENGTH_CAP_AOB pattern needs to be updated for the current game version! !!!");
        // --- END WARNING ---
        return false;
    }
    LogDebug("H2H pattern found at: " + FormatAddress(h2h_found_addr));


    LogDebug("Scanning for Weapon pattern...");
    uintptr_t weapon_found_addr = FindPattern(g_GameBaseAddr, g_GameModuleSize, weapon_bytes, weapon_mask);
    if (weapon_found_addr == 0) {
        LogDebug("Weapon pattern not found!");
        // --- CRITICAL WARNING ---
        LogDebug("!!! WEAPON_STRENGTH_CAP_AOB pattern needs to be updated for the current game version! !!!");
        // --- END WARNING ---
        return false;
    }
    LogDebug("Weapon pattern found at: " + FormatAddress(weapon_found_addr));


    // 4. Apply Memory Patches using found addresses
    if (!ApplyStrengthPatches(h2h_found_addr, weapon_found_addr)) {
        LogDebug("Failed to apply one or both patches.");
        return false; // Stop initialization if patching fails
    }

    LogDebug("StrengthCapFixASI initialized successfully.");
    return true;
}

void CleanupMod()
{
    // Patches applied directly to memory don't typically require cleanup.
    // They persist until the process terminates. No resources allocated here.
    LogDebug("StrengthCapFixASI cleaning up (no action needed).");
    return;
}


// --- Initialization Thread ---
// Runs initialization tasks outside of DllMain.
DWORD WINAPI InitThread(LPVOID lpParam)
{
    // Optional: Add a delay if needed, though likely unnecessary for simple patches.
    // Sleep(500);

    if (InitializeMod()) {
        return TRUE; // Indicate success
    }
    else {
        LogDebug("Initialization failed.");
        return FALSE; // Indicate failure
    }
}


// --- Standard DllMain ---
// Entry point called by the ASI Loader.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        g_DllHandle = hModule;
        DisableThreadLibraryCalls(hModule);

        // Start initialization on a separate thread.
        HANDLE hThread = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread); // We don't need to manage the thread further.
        }
        else {
            // Failed to create init thread, patches won't be applied.
            LogDebug("FATAL: Failed to create initialization thread!");
            // Can optionally return FALSE from DllMain if this failure is unacceptable.
        }
    }
    break;

    case DLL_PROCESS_DETACH:
        // Call cleanup, although it currently does nothing.
        CleanupMod();
        break;

    case DLL_THREAD_ATTACH: // Fall through
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE; // Always return TRUE from DllMain unless attach fails critically.
}