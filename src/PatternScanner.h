// File: PatternScanner.h

#pragma once // Or use #ifndef PATTERN_SCANNER_H ... #endif guards

#include <vector>   // For std::vector
#include <string>   // For std::string
#include <cstdint>  // For uint8_t, uintptr_t
#include <cstddef>  // For size_t

// Optional: Define a namespace for these utility functions
namespace PatternScan
{
    /**
     * @brief Parses an AOB string (e.g., "AA BB ?? CC") into byte and mask vectors.
     * @param aob_str The input AOB string.
     * @param out_bytes Vector to store the parsed bytes (placeholders for wildcards).
     * @param out_mask Vector indicating wildcards (true = wildcard, false = specific byte).
     * @return True if parsing was successful, false otherwise.
     */
    bool ParseAOBString(
        const std::string& aob_str,
        std::vector<uint8_t>& out_bytes,
        std::vector<bool>& out_mask);

    /**
     * @brief Finds a pattern (bytes with mask) within a memory region.
     * @param start_address The beginning address of the memory region to search.
     * @param region_size The size of the memory region to search.
     * @param pattern_bytes The byte values to search for.
     * @param pattern_mask A mask indicating which bytes are wildcards (true = wildcard).
     * @return The starting address where the pattern was found, or 0 if not found.
     */
    uintptr_t FindPattern(
        uintptr_t start_address,
        size_t region_size,
        const std::vector<uint8_t>& pattern_bytes,
        const std::vector<bool>& pattern_mask);

} // namespace PatternScan