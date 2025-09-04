/**
 * @file ghoststr.hpp
 * @brief A C++20 compile-time string obfuscation library (AES-CTR/ChaCha20 + SipHash)
 *
 * This library provides compile-time string encryption and obfuscation capabilities
 * to protect string literals from appearing in plain text within compiled binaries.
 * Compared to simple XOR schemes, it uses a **stream cipher keystream** (AES-128 in CTR mode by default,
 * or ChaCha20 as an alternative) and a **strong keyed hash** (SipHash-2-4) for key derivation.
 *
 * Key features:
 * - Compile-time encryption using consteval functions
 * - Robust stream ciphers: AES-128-CTR (default) or ChaCha20 (20 rounds)
 * - Strong keyed hashing (SipHash-2-4) for key derivation (fallback FNV-1a if disabled)
 * - Optional character substitution (ASCII printable)
 * - Support for all C++ character types (char, wchar_t, char8_t, char16_t, char32_t)
 * - Automatic key generation based on file location and build context
 * - Secure memory clearing after use (RAII-based scoped access)
 * - Backwards-compatible API with original macros (ghostStr, ghostStr_w, …)
 *
 * @note Requires C++20 to guarantee compile-time encryption (consteval).
 * @note Cipher selection: define `GHOSTSTR_STREAM_CIPHER` to `GHOSTSTR_CIPHER_CHACHA20`
 *       before including this header to use ChaCha20 instead of AES-CTR.
 * @note Hash selection: define `GHOSTSTR_USE_SIPHASH 0` to fallback to FNV-1a (not recommended).
 *
 * @author edohb
 * @version 2.0
 */

#pragma once

#if __cplusplus < 202002L
#  error "ghoststr requires C++20 to guarantee compile-time encryption (consteval). Use /std:c++20 or -std=c++20"
#endif

#include <array>
#include <string_view>
#include <string>
#include <type_traits>
#include <cstdint>
#include <cstring>
#include <utility>

#if defined(_MSC_VER)
#include <intrin.h>
#define GHOSTSTR_FORCE_INLINE __forceinline
#define GHOSTSTR_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define GHOSTSTR_FORCE_INLINE __attribute__((always_inline)) inline
#define GHOSTSTR_NOINLINE __attribute__((noinline))
#else
#define GHOSTSTR_FORCE_INLINE inline
#define GHOSTSTR_NOINLINE
#endif

/** @brief Mark functions that must be evaluated at compile-time. */
#define GHOSTSTR_CONSTEVAL consteval

#ifndef GHOSTSTR_USE_TIME_SEED
/**
 * @def GHOSTSTR_USE_TIME_SEED
 * @brief When set to 1, mixes __DATE__/__TIME__ into key derivation for per-build variance.
 * @note Default: 0 (deterministic across builds).
 */
#define GHOSTSTR_USE_TIME_SEED 0
#endif

#ifndef GHOSTSTR_ENABLE_SUBSTITUTION
/**
 * @def GHOSTSTR_ENABLE_SUBSTITUTION
 * @brief Enable printable-ASCII substitution layer (minor obfuscation on top of keystream).
 * @note Default: 1
 */
#define GHOSTSTR_ENABLE_SUBSTITUTION 1
#endif

/** @name Stream cipher selection
 *  Define GHOSTSTR_STREAM_CIPHER to choose the keystream algorithm.
 *  @{
 */
#define GHOSTSTR_CIPHER_CHACHA20 1   ///< Use ChaCha20 (20 rounds) keystream
#define GHOSTSTR_CIPHER_AESCTR   2   ///< Use AES-128 in CTR mode keystream (default)
#ifndef GHOSTSTR_STREAM_CIPHER
#define GHOSTSTR_STREAM_CIPHER GHOSTSTR_CIPHER_AESCTR
#endif
/** @} */

/**
 * @def GHOSTSTR_USE_SIPHASH
 * @brief Use SipHash-2-4 (keyed) for compile-time const_hash if 1, else fallback to FNV-1a.
 * @note Default: 1 (recommended).
 */
#ifndef GHOSTSTR_USE_SIPHASH
#define GHOSTSTR_USE_SIPHASH 1
#endif

/**
 * @namespace ghoststr
 * @brief Main namespace for the ghoststr string obfuscation library.
 *
 * Contains compile-time key derivation, stream ciphers (ChaCha20 / AES-CTR),
 * secure-zero utilities, and the `obfuscated_string` container with RAII access.
 */
namespace ghoststr {
    /**
     * @brief 32-bit left rotation.
     * @param x Input value
     * @param r Rotate amount
     * @return Rotated value
     */
    GHOSTSTR_FORCE_INLINE constexpr std::uint32_t rotl32(std::uint32_t x, int r) noexcept {
        return static_cast<std::uint32_t>((x << r) | (x >> (32 - r)));
    }

    /**
     * @brief 64-bit left rotation.
     * @param x Input value
     * @param r Rotate amount
     * @return Rotated value
     */
    GHOSTSTR_FORCE_INLINE constexpr std::uint64_t rotl64(std::uint64_t x, int r) noexcept {
        return (x << r) | (x >> (64 - r));
    }

    /**
     * @brief splitmix64 mixer for pseudo-random derivations (consteval friendly).
     * @param x Seed value
     * @return Mixed 64-bit value and updated seed
     */
    GHOSTSTR_FORCE_INLINE constexpr std::pair<std::uint64_t, std::uint64_t> splitmix64(std::uint64_t x) noexcept {
        std::uint64_t updated = x + 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = updated;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return {z ^ (z >> 31), updated};
    }

    /**
     * @brief FNV-1a 64-bit hash (fallback, non-cryptographic).
     * @param str Pointer to data
     * @param len Length in bytes
     * @return 64-bit hash
     * @note Used only if GHOSTSTR_USE_SIPHASH == 0.
     */
    GHOSTSTR_CONSTEVAL std::uint64_t const_hash_fnv1a(const char* str, std::size_t len) noexcept {
        std::uint64_t hash = 0xCBF29CE484222325ULL;
        for (std::size_t i = 0; i < len; ++i) {
            hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(str[i]));
            hash *= 0x100000001B3ULL;
        }
        return hash;
    }

#if GHOSTSTR_USE_SIPHASH
    /**
     * @brief SipHash-2-4 keyed hash (little-endian block packing).
     * @param data Pointer to bytes
     * @param len Length in bytes
     * @param k0 First 64-bit key
     * @param k1 Second 64-bit key
     * @return 64-bit MAC
     * @note consteval-friendly implementation for compile-time hashing.
     */
    GHOSTSTR_CONSTEVAL std::uint64_t siphash_24(const char* data, std::size_t len,
        std::uint64_t k0, std::uint64_t k1) noexcept {
        std::uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
        std::uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
        std::uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
        std::uint64_t v3 = 0x7465646279746573ULL ^ k1;

        auto sip_round = [&](int n) constexpr {
            for (int i = 0; i < n; ++i) {
                v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
                v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
                v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
                v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
            }
            };

        std::size_t i = 0;
        while (i + 8 <= len) {
            std::uint64_t m = 0;
            for (int b = 0; b < 8; ++b) {
                m |= (std::uint64_t)(unsigned char)data[i + b] << (8 * b);
            }
            v3 ^= m; sip_round(2); v0 ^= m;
            i += 8;
        }

        std::uint64_t b = (std::uint64_t)len << 56;
        int rem = (int)(len - i);
        for (int bidx = 0; bidx < rem; ++bidx) {
            b |= (std::uint64_t)(unsigned char)data[i + bidx] << (8 * bidx);
        }

        v3 ^= b; sip_round(2); v0 ^= b;
        v2 ^= 0xFF; sip_round(4);
        return (v0 ^ v1) ^ (v2 ^ v3);
    }
#endif

    /**
     * @brief Public compile-time hash used in key derivation.
     * @param str Pointer to bytes
     * @param len Length in bytes
     * @return 64-bit hash
     * @note Default is SipHash-2-4 keyed with per-build deterministic keys; FNV-1a fallback.
     */
    GHOSTSTR_CONSTEVAL std::uint64_t const_hash(const char* str, std::size_t len) noexcept {
#if GHOSTSTR_USE_SIPHASH
        std::uint64_t seed = 0x3C79AC492BA7B653ULL ^ 0x1C69B3F74AC4AE35ULL;
#if GHOSTSTR_USE_TIME_SEED
        std::uint64_t k0src = const_hash_fnv1a(__DATE__ __TIME__, sizeof(__DATE__ __TIME__) - 1);
#else
        std::uint64_t k0src = 0x9E3779B97F4A7C15ULL;
#endif
        seed ^= k0src;
        auto [k0, seed2] = splitmix64(seed);
        auto [k1, _] = splitmix64(seed2);
        return siphash_24(str, len, k0, k1);
#else
        return const_hash_fnv1a(str, len);
#endif
    }

    /**
     * @brief Build-dependent seed mixed into key derivation.
     * @return 64-bit seed (fixed or mixed with __DATE__/__TIME__).
     */
    GHOSTSTR_CONSTEVAL std::uint64_t time_seed() noexcept {
#if GHOSTSTR_USE_TIME_SEED
        return const_hash(__DATE__ __TIME__, sizeof(__DATE__ __TIME__) - 1);
#else
        return 0xA0761D6478BD642FULL;
#endif
    }
    /**
     * @brief Builds a unique 64-bit key from file hash, line, index, and counter.
     * @tparam FileHash Hash of the source file path (compile-time)
     * @tparam Line     Source line number
     * @tparam Index    Additional index to differentiate multiple literals on same line
     * @tparam Counter  Compiler counter for uniqueness
     * @return 64-bit derived key
     */
    template<std::uint64_t FileHash, int Line, std::size_t Index, int Counter>
    GHOSTSTR_CONSTEVAL std::uint64_t build_key() noexcept {
        std::uint64_t s = 0x9E3779B97F4A7C15ULL ^ FileHash ^ time_seed();
        auto [a, _1] = splitmix64(s ^ (static_cast<std::uint64_t>(Line) * 0xD1342543DE82EF95ULL));
        auto [b, _2] = splitmix64(s ^ (static_cast<std::uint64_t>(Index) * 0x94D049BB133111EBULL));
        auto [c, _3] = splitmix64(s ^ (static_cast<std::uint64_t>(Counter) * 0xBF58476D1CE4E5B9ULL));
        std::uint64_t out = a ^ rotl64(b, 17) ^ rotl64(c, 33);
        out ^= out >> 30; out *= 0xBF58476D1CE4E5B9ULL;
        out ^= out >> 27; out *= 0x94D049BB133111EBULL;
        out ^= out >> 31;
        return out;
    }

    /**
     * @brief Creates a compiler memory barrier to prevent reordering around sensitive ops.
     * @note Ensures zeroing isn't optimized away.
     */
    GHOSTSTR_NOINLINE inline void compiler_barrier() noexcept {
#if defined(_MSC_VER)
        _ReadWriteBarrier();
#else
        asm volatile("" ::: "memory");
#endif
    }

    /**
     * @brief Securely zeroes memory to prevent data recovery.
     * @tparam T POD element type
     * @param ptr Pointer to the buffer
     * @param size Number of elements to wipe
     * @note Uses volatile writes and a compiler barrier. On MSVC uses `__stosb`.
     */
    template<typename T>
    GHOSTSTR_NOINLINE void secure_zero(T* ptr, std::size_t size) noexcept {
#if defined(_MSC_VER)
        __stosb(reinterpret_cast<unsigned char*>(ptr), 0, size * sizeof(T));
        compiler_barrier();
#else
        volatile std::uint8_t* vptr = reinterpret_cast<volatile std::uint8_t*>(ptr);
        for (std::size_t i = 0; i < size * sizeof(T); ++i) vptr[i] = 0;
        compiler_barrier();
#endif
    }

#if GHOSTSTR_STREAM_CIPHER == GHOSTSTR_CIPHER_CHACHA20
    /**
     * @brief Parameters for ChaCha20 keystream.
     */
    struct chacha20_params {
        std::array<std::uint32_t, 8>  key;    ///< 256-bit key (8x u32)
        std::array<std::uint32_t, 3>  nonce;  ///< 96-bit nonce (3x u32)
        std::uint32_t                 counter;///< 32-bit block counter
    };

    /**
     * @brief Derive ChaCha20 parameters from two 64-bit keys.
     * @param k1 First 64-bit key
     * @param k2 Second 64-bit key
     * @return Parameters with key/nonce/counter filled
     */
    GHOSTSTR_CONSTEVAL chacha20_params derive_chacha_params(std::uint64_t k1, std::uint64_t k2) noexcept {
        std::uint64_t seed = 0xDEADBEEFCAFEBABEULL ^ k1 ^ rotl64(k2, 23);
        chacha20_params p{};
        for (int i = 0; i < 8; ++i) {
            auto [val, new_seed] = splitmix64(seed);
            p.key[i] = static_cast<std::uint32_t>(val & 0xFFFFFFFFu);
            seed = new_seed;
        }
        for (int i = 0; i < 3; ++i) {
            auto [val, new_seed] = splitmix64(seed);
            p.nonce[i] = static_cast<std::uint32_t>(val & 0xFFFFFFFFu);
            seed = new_seed;
        }
        auto [val, _] = splitmix64(seed);
        p.counter = static_cast<std::uint32_t>(val & 0xFFFFFFFFu);
        return p;
    }

    /**
     * @brief ChaCha20 quarter round (in-place).
     */
    GHOSTSTR_FORCE_INLINE constexpr void chacha_quarterround(std::uint32_t& a, std::uint32_t& b,
        std::uint32_t& c, std::uint32_t& d) noexcept {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    /**
     * @brief Generate a 64-byte ChaCha20 keystream block.
     * @param p ChaCha20 parameters (key/nonce)
     * @param counter Block counter
     * @return 64 bytes of keystream
     */
    constexpr std::array<std::uint8_t, 64> chacha20_block(const chacha20_params& p,
        std::uint32_t counter) noexcept {
        std::array<std::uint32_t, 16> state{
            0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u, // "expand 32-byte k"
            p.key[0], p.key[1], p.key[2], p.key[3],
            p.key[4], p.key[5], p.key[6], p.key[7],
            counter, p.nonce[0], p.nonce[1], p.nonce[2]
        };
        std::array<std::uint32_t, 16> x = state;
        for (int i = 0; i < 10; ++i) {
            // column rounds
            chacha_quarterround(x[0], x[4], x[8], x[12]);
            chacha_quarterround(x[1], x[5], x[9], x[13]);
            chacha_quarterround(x[2], x[6], x[10], x[14]);
            chacha_quarterround(x[3], x[7], x[11], x[15]);
            // diagonal rounds
            chacha_quarterround(x[0], x[5], x[10], x[15]);
            chacha_quarterround(x[1], x[6], x[11], x[12]);
            chacha_quarterround(x[2], x[7], x[8], x[13]);
            chacha_quarterround(x[3], x[4], x[9], x[14]);
        }
        for (int i = 0; i < 16; ++i) x[i] += state[i];

        std::array<std::uint8_t, 64> out{};
        for (int i = 0; i < 16; ++i) {
            out[i * 4 + 0] = static_cast<std::uint8_t>(x[i] & 0xFF);
            out[i * 4 + 1] = static_cast<std::uint8_t>((x[i] >> 8) & 0xFF);
            out[i * 4 + 2] = static_cast<std::uint8_t>((x[i] >> 16) & 0xFF);
            out[i * 4 + 3] = static_cast<std::uint8_t>((x[i] >> 24) & 0xFF);
        }
        return out;
    }
#endif // CHACHA20

#if GHOSTSTR_STREAM_CIPHER == GHOSTSTR_CIPHER_AESCTR
    /**
     * @brief Parameters for AES-128 CTR (key + 128-bit IV: nonce||counter).
     */
    struct aes128_params {
        std::array<std::uint8_t, 16> key;  ///< 128-bit AES key
        std::array<std::uint8_t, 16> iv;   ///< 128-bit IV (nonce||counter)
    };

    /**
     * @brief Derive AES-128 key and IV from two 64-bit keys.
     * @param k1 First 64-bit key
     * @param k2 Second 64-bit key
     * @return AES parameters
     */
    GHOSTSTR_CONSTEVAL aes128_params derive_aes_params(std::uint64_t k1, std::uint64_t k2) noexcept {
        std::uint64_t seed = 0xBADC0FFEE0DDF00DULL ^ k1 ^ rotl64(k2, 7);
        aes128_params p{};
        for (int i = 0; i < 16; ++i) {
            auto [val, new_seed] = splitmix64(seed);
            p.key[i] = static_cast<std::uint8_t>(val & 0xFF);
            seed = new_seed;
        }
        for (int i = 0; i < 16; ++i) {
            auto [val, new_seed] = splitmix64(seed);
            p.iv[i] = static_cast<std::uint8_t>(val & 0xFF);
            seed = new_seed;
        }
        return p;
    }

    /** @brief Build the AES S-box (precomputed). */
    GHOSTSTR_CONSTEVAL std::array<std::uint8_t, 256> make_sbox() {
        return std::array<std::uint8_t, 256>{
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };
    }
    /** @brief Global AES S-box table. */
    constexpr auto AES_SBOX = make_sbox();

    /** @brief Multiply by x in GF(2^8) for AES MixColumns. */
    GHOSTSTR_FORCE_INLINE constexpr std::uint8_t xtime(std::uint8_t x) {
        return (std::uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
    }

    /**
     * @brief Expand AES-128 key to 176 bytes of round keys.
     * @param key 16-byte key
     * @return Expanded round keys (176 bytes)
     */
    constexpr std::array<std::uint8_t, 176> aes_key_expand_128(const std::array<std::uint8_t, 16>& key) {
        constexpr std::uint8_t Rcon[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36 };
        std::array<std::uint8_t, 176> rk{};
        
        // Copy initial key
        for (int i = 0; i < 16; ++i) {
            rk[i] = key[i];
        }
        
        // Expand key
        for (int i = 16; i < 176; i += 4) {
            std::uint8_t t0 = rk[i - 4];
            std::uint8_t t1 = rk[i - 3];
            std::uint8_t t2 = rk[i - 2];
            std::uint8_t t3 = rk[i - 1];
            
            if ((i % 16) == 0) {
                // RotWord
                std::uint8_t tmp = t0;
                t0 = t1;
                t1 = t2;
                t2 = t3;
                t3 = tmp;
                
                // SubBytes
                t0 = AES_SBOX[t0];
                t1 = AES_SBOX[t1];
                t2 = AES_SBOX[t2];
                t3 = AES_SBOX[t3];
                
                // XOR with Rcon
                t0 ^= Rcon[i / 16];
            }
            
            rk[i + 0] = rk[i - 16 + 0] ^ t0;
            rk[i + 1] = rk[i - 16 + 1] ^ t1;
            rk[i + 2] = rk[i - 16 + 2] ^ t2;
            rk[i + 3] = rk[i - 16 + 3] ^ t3;
        }
        
        return rk;
    }

    /** @brief AES SubBytes step. */
    constexpr void aes_sub_bytes(std::uint8_t s[16]) {
        for (int i = 0; i < 16; ++i) s[i] = AES_SBOX[s[i]];
    }

    /** @brief AES ShiftRows step. */
    constexpr void aes_shift_rows(std::uint8_t s[16]) {
        std::uint8_t t[16];
        t[0] = s[0];  t[1] = s[5];  t[2] = s[10]; t[3] = s[15];
        t[4] = s[4];  t[5] = s[9];  t[6] = s[14]; t[7] = s[3];
        t[8] = s[8];  t[9] = s[13]; t[10] = s[2];  t[11] = s[7];
        t[12] = s[12]; t[13] = s[1];  t[14] = s[6];  t[15] = s[11];
        for (int i = 0; i < 16; ++i) s[i] = t[i];
    }

    /** @brief AES MixColumns step. */
    constexpr void aes_mix_columns(std::uint8_t s[16]) {
        for (int c = 0; c < 4; ++c) {
            int i = 4 * c;
            std::uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
            std::uint8_t r0 = (std::uint8_t)(xtime(a0) ^ (a1 ^ xtime(a1)) ^ a2 ^ a3);
            std::uint8_t r1 = (std::uint8_t)(a0 ^ xtime(a1) ^ (a2 ^ xtime(a2)) ^ a3);
            std::uint8_t r2 = (std::uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (a3 ^ xtime(a3)));
            std::uint8_t r3 = (std::uint8_t)((a0 ^ xtime(a0)) ^ a1 ^ a2 ^ xtime(a3));
            s[i] = r0; s[i + 1] = r1; s[i + 2] = r2; s[i + 3] = r3;
        }
    }

    /** @brief XOR AddRoundKey step. */
    constexpr void aes_add_round_key(std::uint8_t s[16], const std::uint8_t* rk) {
        for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
    }

    /**
     * @brief AES-128 block encryption (ECB single block).
     * @param rk Round keys (176 bytes)
     * @param in 16-byte input block
     * @return 16-byte encrypted block
     */
    constexpr std::array<std::uint8_t, 16> aes_encrypt_block(
        const std::array<std::uint8_t, 176>& rk,
        const std::array<std::uint8_t, 16>& in) {
        std::uint8_t s[16];
        for (int i = 0; i < 16; ++i) s[i] = in[i];
        aes_add_round_key(s, rk.data());
        for (int r = 1; r <= 9; ++r) {
            aes_sub_bytes(s); aes_shift_rows(s); aes_mix_columns(s);
            aes_add_round_key(s, rk.data() + 16 * r);
        }
        aes_sub_bytes(s); aes_shift_rows(s);
        aes_add_round_key(s, rk.data() + 160);
        std::array<std::uint8_t, 16> out{};
        for (int i = 0; i < 16; ++i) out[i] = s[i];
        return out;
    }
#endif // AES CTR

    /**
     * @brief Compile-time keystream byte generator at given byte offset.
     * @tparam K1 First 64-bit key
     * @tparam K2 Second 64-bit key
     * @param offset_bytes Absolute byte offset within the stream
     * @return Keystream byte
     */
    template<std::uint64_t K1, std::uint64_t K2>
    constexpr std::uint8_t keystream_byte_compile(std::size_t offset_bytes) noexcept {
#if GHOSTSTR_STREAM_CIPHER == GHOSTSTR_CIPHER_CHACHA20
        constexpr std::size_t BLK = 64;
        constexpr auto P = derive_chacha_params(K1, K2);
        std::uint32_t ctr = P.counter + static_cast<std::uint32_t>(offset_bytes / BLK);
        auto block = chacha20_block(P, ctr);
        return block[offset_bytes % BLK];
#elif GHOSTSTR_STREAM_CIPHER == GHOSTSTR_CIPHER_AESCTR
        constexpr std::size_t BLK = 16;
        constexpr auto P = derive_aes_params(K1, K2);
        auto rk = aes_key_expand_128(P.key);
        std::size_t bi = offset_bytes / BLK;
        std::array<std::uint8_t, 16> counter_block = P.iv;
        std::uint64_t carry = bi;
        for (int i = 15; i >= 0 && carry; --i) {
            std::uint16_t sum = (std::uint16_t)counter_block[i] + (std::uint16_t)(carry & 0xFF);
            counter_block[i] = (std::uint8_t)(sum & 0xFF);
            carry >>= 8;
        }
        auto ks = aes_encrypt_block(rk, counter_block);
        return ks[offset_bytes % BLK];
#endif
    }

    /**
     * @brief Runtime keystream byte generator at given byte offset.
     * @tparam K1 First 64-bit key
     * @tparam K2 Second 64-bit key
     * @param offset_bytes Absolute byte offset within the stream
     * @return Keystream byte
     */
    template<std::uint64_t K1, std::uint64_t K2>
    GHOSTSTR_FORCE_INLINE std::uint8_t keystream_byte_runtime(std::size_t offset_bytes) noexcept {
#if GHOSTSTR_STREAM_CIPHER == GHOSTSTR_CIPHER_CHACHA20
        static const chacha20_params P = [] { return derive_chacha_params(K1, K2); }();
        const std::size_t BLK = 64;
        std::uint32_t ctr = P.counter + static_cast<std::uint32_t>(offset_bytes / BLK);
        auto block = chacha20_block(P, ctr);
        return block[offset_bytes % BLK];
#elif GHOSTSTR_STREAM_CIPHER == GHOSTSTR_CIPHER_AESCTR
        static const aes128_params P = [] { return derive_aes_params(K1, K2); }();
        static const std::array<std::uint8_t, 176> RK = aes_key_expand_128(P.key);
        const std::size_t BLK = 16;
        std::size_t bi = offset_bytes / BLK;x
        std::array<std::uint8_t, 16> counter_block = P.iv;
        std::uint64_t carry = bi;
        for (int i = 15; i >= 0 && carry; --i) {
            std::uint16_t sum = (std::uint16_t)counter_block[i] + (std::uint16_t)(carry & 0xFF);
            counter_block[i] = (std::uint8_t)(sum & 0xFF);
            carry >>= 8;
        }
        auto ks = aes_encrypt_block(RK, counter_block);
        return ks[offset_bytes % BLK];
#endif
    }

    /**
     * @brief Performs character substitution for printable ASCII (optional).
     * @tparam CharT Character type
     * @param c Input character
     * @param key Key material for offset derivation
     * @return Possibly substituted character
     * @note Enabled only when GHOSTSTR_ENABLE_SUBSTITUTION == 1 and CharT == char.
     */
    template<typename CharT>
    constexpr CharT substitute_encrypt(CharT c, std::uint64_t key) noexcept {
#if GHOSTSTR_ENABLE_SUBSTITUTION
        if constexpr (std::is_same_v<CharT, char>) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 32 && uc <= 126) {
                std::uint8_t off = static_cast<std::uint8_t>((key >> 8) & 0x3F);
                return static_cast<CharT>(32 + ((uc - 32 + off) % 95));
            }
        }
#endif
        return c;
    }

    /**
     * @brief Compile-time encrypted string with secure runtime access.
     * @tparam CharT Character type (char, wchar_t, char8_t, char16_t, char32_t)
     * @tparam N     Size of the string including null terminator
     * @tparam Key1  First 64-bit key
     * @tparam Key2  Second 64-bit key
     *
     * Stores the encrypted string (via stream cipher keystream + optional substitution)
     * and exposes RAII-based accessors that wipe decrypted memory on destruction.
     */
    template<typename CharT, std::size_t N, std::uint64_t Key1, std::uint64_t Key2>
    class obfuscated_string {
        static_assert(N > 0, "String length must be greater than 0");

    public:
        using value_type = CharT;                ///< Character type used by this string
        using size_type = std::size_t;           ///< Size/index type
        using pointer = value_type*;             ///< Mutable pointer
        using const_pointer = const value_type*; ///< Const pointer

        /**
         * @brief RAII wrapper for temporary access to decrypted data.
         *
         * Decrypts on construction into an internal buffer and
         * securely wipes it on destruction. Non-copyable and non-movable.
         */
        struct scoped_view {
            std::array<CharT, N> buffer;                    ///< Decrypted buffer
            std::basic_string_view<CharT> view;             ///< View of decrypted data

            /** @brief Decrypt into buffer. */
            explicit scoped_view(const obfuscated_string& self)
                : buffer(self.decrypt_copy()), view(buffer.data(), N > 0 ? N - 1 : 0) {
            }

            /** @brief Wipe buffer on destruction. */
            ~scoped_view() { secure_zero(buffer.data(), buffer.size()); }

            scoped_view(const scoped_view&) = delete;
            scoped_view& operator=(const scoped_view&) = delete;
            scoped_view(scoped_view&&) = delete;
            scoped_view& operator=(scoped_view&&) = delete;

            /** @return Pointer to decrypted data (null-terminated). */
            const_pointer data() const noexcept { return view.data(); }

            /** @return C-style string pointer (null-terminated). */
            const_pointer c_str() const noexcept { return view.data(); }

            /** @return Length excluding null terminator. */
            std::size_t size() const noexcept { return view.size(); }

            /** @brief Implicit conversion to string_view. */
            operator std::basic_string_view<CharT>() const noexcept { return view; }
        };

        /**
         * @brief RAII holder exposing a stable C-string pointer.
         *
         * Combines a `scoped_view` (manages lifetime and wiping) with
         * direct pointer access for C APIs.
         */
        struct c_str_holder {
            scoped_view sv;               ///< Underlying scoped view
            const CharT* ptr;             ///< C-string pointer
            std::size_t len;              ///< String length

            /** @brief Construct and decrypt. */
            explicit c_str_holder(const obfuscated_string& self)
                : sv(self), ptr(sv.data()), len(sv.size()) {
            }

            c_str_holder(const c_str_holder&) = delete;
            c_str_holder& operator=(const c_str_holder&) = delete;
            c_str_holder(c_str_holder&&) = delete;
            c_str_holder& operator=(c_str_holder&&) = delete;
        };

        /**
         * @brief Create a C-string RAII holder.
         * @return Holder that wipes decrypted memory on destruction.
         * @example
         * ```cpp
         * auto h = secret.c_str_scoped();
         * printf("%s\n", h.ptr);
         * ```
         */
        c_str_holder c_str_scoped() const noexcept { return c_str_holder{ *this }; }

    private:
        std::array<CharT, N> storage_; ///< Encrypted storage

        /**
         * @brief Encrypt a string literal at compile time.
         * @param str Source string literal
         * @return Encrypted array with null terminator preserved
         * @note Uses stream keystream (ChaCha20 or AES-CTR) per-byte across CharT width,
         *       then optional ASCII substitution for `char`.
         */
        static constexpr std::array<CharT, N> encrypt_string(const CharT* str) noexcept {
            std::array<CharT, N> result{};
            using U = std::make_unsigned_t<CharT>;
            for (size_type i = 0; i < N - 1; ++i) {
                U u = static_cast<U>(str[i]);
                for (std::size_t b = 0; b < sizeof(CharT); ++b) {
                    std::size_t off = i * sizeof(CharT) + b;
                    std::uint8_t ks = keystream_byte_compile<Key1, Key2>(off);
                    U mask = static_cast<U>(static_cast<U>(ks) << (8 * b));
                    u = static_cast<U>(u ^ mask);
                }
                CharT c = static_cast<CharT>(u);
                c = substitute_encrypt(c, Key2);
                result[i] = c;
            }
            result[N - 1] = static_cast<CharT>(0);
            return result;
        }

    public:
        /**
         * @brief Construct from a string literal (compile-time encryption).
         * @param str String literal (must include null terminator)
         */
        constexpr obfuscated_string(const CharT(&str)[N]) noexcept
            : storage_(encrypt_string(str)) {
        }

        /**
         * @brief Get string length (excluding null terminator).
         * @return Length in characters
         */
        constexpr size_type size() const noexcept { return N > 0 ? N - 1 : 0; }

        /**
         * @brief Alias for size().
         * @return Length in characters
         */
        constexpr size_type length() const noexcept { return size(); }

        /**
         * @brief Decrypt a copy of the string (runtime) into a new array.
         * @return Array containing decrypted data (null-terminated)
         * @warning Caller should avoid storing long-lived copies; prefer RAII accessors.
         */
        GHOSTSTR_NOINLINE std::array<CharT, N> decrypt_copy() const noexcept {
            std::array<CharT, N> out{};
            using U = std::make_unsigned_t<CharT>;
            for (size_type i = 0; i < N - 1; ++i) {
                CharT c = storage_[i];
#if GHOSTSTR_ENABLE_SUBSTITUTION
                if constexpr (std::is_same_v<CharT, char>) {
                    unsigned char uc = static_cast<unsigned char>(c);
                    if (uc >= 32 && uc <= 126) {
                        std::uint8_t off = static_cast<std::uint8_t>((Key2 >> 8) & 0x3F);
                        c = static_cast<CharT>(32 + ((uc - 32 + 95 - (off % 95)) % 95));
                    }
                }
#endif
                U u = static_cast<U>(c);
                for (std::size_t b = 0; b < sizeof(CharT); ++b) {
                    std::size_t off = i * sizeof(CharT) + b;
                    std::uint8_t ks = keystream_byte_runtime<Key1, Key2>(off);
                    U mask = static_cast<U>(static_cast<U>(ks) << (8 * b));
                    u = static_cast<U>(u ^ mask);
                }
                out[i] = static_cast<CharT>(u);
            }
            out[N - 1] = static_cast<CharT>(0);
            compiler_barrier();
            return out;
        }

        /**
         * @brief Create a scoped view of decrypted data (auto-wiped).
         * @return RAII view for safe temporary access.
         */
        scoped_view scoped() const noexcept { return scoped_view(*this); }

        /**
         * @brief Convert to std::basic_string (copy).
         * @return Plain string containing decrypted data
         * @warning Plain strings are not securely wiped; use sparingly.
         */
        std::basic_string<CharT> str() const {
            auto tmp = decrypt_copy();
            return std::basic_string<CharT>(tmp.data(), size());
        }

        /**
         * @brief Securely clear the encrypted storage in place.
         * @note After calling this, the instance cannot be decrypted.
         */
        GHOSTSTR_NOINLINE void clear() noexcept { secure_zero(storage_.data(), storage_.size()); }

        /**
         * @brief Compare decrypted contents with another obfuscated string.
         * @tparam C2 Other char type
         * @tparam M  Other size
         * @tparam K1b Other Key1
         * @tparam K2b Other Key2
         * @param other Instance to compare with
         * @return true if equal, false otherwise
         * @note For constant-time comparison, replace with an accumulator-based loop.
         */
        template<typename C2, std::size_t M, std::uint64_t K1b, std::uint64_t K2b>
        bool equals(const obfuscated_string<C2, M, K1b, K2b>& other) const noexcept {
            if constexpr (!std::is_same_v<CharT, C2>) return false;
            if (this->size() != other.size()) return false;
            auto a = this->decrypt_copy();
            auto b = other.decrypt_copy();
            std::basic_string_view<CharT> va(a.data(), this->size());
            std::basic_string_view<CharT> vb(b.data(), other.size());
            return va == vb;
        }

        /** @brief Equality operator (obfuscated_string). */
        bool operator==(const obfuscated_string& other) const noexcept { return equals(other); }

        /** @brief Equality operator (C-string). */
        bool operator==(const CharT* s) const noexcept {
            auto d = decrypt_copy();
            return std::basic_string_view<CharT>(d.data(), size()) == s;
        }

        /** @brief Equality operator (string_view). */
        bool operator==(std::basic_string_view<CharT> sv) const noexcept {
            auto d = decrypt_copy();
            return std::basic_string_view<CharT>(d.data(), size()) == sv;
        }
    };

    /**
     * @brief Create an obfuscated string with specified keys.
     * @tparam CharT Character type
     * @tparam N     Length including null terminator
     * @tparam K1    First 64-bit key
     * @tparam K2    Second 64-bit key
     * @param str    String literal
     * @return obfuscated_string instance
     */
    template<typename CharT, std::size_t N, std::uint64_t K1, std::uint64_t K2>
    constexpr auto make_obfuscated_with_keys(const CharT(&str)[N]) noexcept {
        return obfuscated_string<CharT, N, K1, K2>(str);
    }

} // namespace ghoststr

/**
 * @brief Internal macro for creating obfuscated strings with site-specific keys.
 * @param STR_LIT String literal
 * @param IDX     Index to disambiguate multiple literals
 * @note Keys are derived from file path hash, line, index, and compiler counter.
 */
#define GHOSTSTR_MAKE_WITH_SITE(STR_LIT, IDX)                                                   \
    []() constexpr {                                                                            \
        constexpr auto key1 = ::ghoststr::build_key<                                            \
            ::ghoststr::const_hash(__FILE__, sizeof(__FILE__) - 1),                             \
            __LINE__, (IDX), __COUNTER__>();                                                    \
        constexpr auto key2 = ::ghoststr::build_key<                                            \
            ::ghoststr::const_hash(__FILE__, sizeof(__FILE__) - 1),                             \
            __LINE__, (IDX) + 0x42, __COUNTER__>();                                             \
        return ::ghoststr::make_obfuscated_with_keys<                                           \
            std::remove_cv_t<std::remove_reference_t<decltype(STR_LIT[0])>>,                    \
            sizeof(STR_LIT) / sizeof(decltype(STR_LIT[0])),                                     \
            key1, key2>(STR_LIT);                                                               \
    }()

/**
 * @brief Creates an obfuscated char string with automatic key generation.
 * @param str `char` string literal
 * @return obfuscated_string instance
 */
#define ghostStr(str)      GHOSTSTR_MAKE_WITH_SITE(str, 0)

/**
 * @brief Creates an obfuscated wide string with automatic key generation.
 * @param str `wchar_t` string literal
 * @return obfuscated_string<wchar_t,...>
 */
#define ghostStr_w(str)    GHOSTSTR_MAKE_WITH_SITE(str, 1)

/**
 * @brief Creates an obfuscated UTF-8 string with automatic key generation.
 * @param str `char8_t` string literal
 * @return obfuscated_string<char8_t,...>
 */
#define ghostStr_u8(str)   GHOSTSTR_MAKE_WITH_SITE(str, 2)

/**
 * @brief Creates an obfuscated UTF-16 string with automatic key generation.
 * @param str `char16_t` string literal
 * @return obfuscated_string<char16_t,...>
 */
#define ghostStr_u16(str)  GHOSTSTR_MAKE_WITH_SITE(str, 3)

/**
 * @brief Creates an obfuscated UTF-32 string with automatic key generation.
 * @param str `char32_t` string literal
 * @return obfuscated_string<char32_t,...>
 */
#define ghostStr_u32(str)  GHOSTSTR_MAKE_WITH_SITE(str, 4)

/**
 * @brief Creates an obfuscated char string with manually specified keys.
 * @param str `char` string literal
 * @param k1  First 64-bit key
 * @param k2  Second 64-bit key
 * @return obfuscated_string<char,...>
 */
#define ghostStr_key(str, k1, k2) \
    (::ghoststr::obfuscated_string<char, sizeof(str), k1, k2>(str))

/**
 * @brief Creates an obfuscated wide string with manually specified keys.
 * @param str `wchar_t` string literal
 * @param k1  First 64-bit key
 * @param k2  Second 64-bit key
 * @return obfuscated_string<wchar_t,...>
 */
#define ghostStr_key_w(str, k1, k2) \
    (::ghoststr::obfuscated_string<wchar_t, sizeof(str)/sizeof(wchar_t), k1, k2>(str))

/**
 * @brief Creates an obfuscated UTF-8 string with manually specified keys.
 * @param str `char8_t` string literal
 * @param k1  First 64-bit key
 * @param k2  Second 64-bit key
 * @return obfuscated_string<char8_t,...>
 */
#define ghostStr_key_u8(str, k1, k2) \
    (::ghoststr::obfuscated_string<char8_t, sizeof(str)/sizeof(char8_t), k1, k2>(str))

/**
 * @brief Creates an obfuscated UTF-16 string with manually specified keys.
 * @param str `char16_t` string literal
 * @param k1  First 64-bit key
 * @param k2  Second 64-bit key
 * @return obfuscated_string<char16_t,...>
 */
#define ghostStr_key_u16(str, k1, k2) \
    (::ghoststr::obfuscated_string<char16_t, sizeof(str)/sizeof(char16_t), k1, k2>(str))

/**
 * @brief Creates an obfuscated UTF-32 string with manually specified keys.
 * @param str `char32_t` string literal
 * @param k1  First 64-bit key
 * @param k2  Second 64-bit key
 * @return obfuscated_string<char32_t,...>
 */
#define ghostStr_key_u32(str, k1, k2) \
    (::ghoststr::obfuscated_string<char32_t, sizeof(str)/sizeof(char32_t), k1, k2>(str))