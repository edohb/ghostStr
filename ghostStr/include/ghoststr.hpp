/**
 * @file ghoststr.hpp
 * @brief A C++20 compile-time string obfuscation library
 * 
 * This library provides compile-time string encryption and obfuscation capabilities
 * to protect string literals from appearing in plain text within compiled binaries.
 * The library uses XOR encryption with position-dependent keys, optional character
 * substitution, and secure memory clearing to provide multiple layers of protection.
 * 
 * Key features:
 * - Compile-time encryption using consteval functions
 * - Multiple encryption layers (XOR + substitution + final XOR)
 * - Support for all C++ character types (char, wchar_t, char8_t, char16_t, char32_t)
 * - Automatic key generation based on file location and build context
 * - Secure memory clearing after use
 * - RAII-based scoped access to decrypted strings
 * 
 * @note Requires C++20 for consteval compile-time encryption guarantees
 * @author edohb
 * @version 1.0
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

#define GHOSTSTR_CONSTEVAL consteval

#ifndef GHOSTSTR_USE_TIME_SEED
#define GHOSTSTR_USE_TIME_SEED 0
#endif

#ifndef GHOSTSTR_ENABLE_SUBSTITUTION
#define GHOSTSTR_ENABLE_SUBSTITUTION 1
#endif

/**
 * @brief Main namespace for the ghoststr string obfuscation library
 * 
 * Contains all functions, classes, and utilities for compile-time string
 * encryption and obfuscation. The namespace provides a clean separation
 * from user code and prevents naming conflicts.
 */
namespace ghoststr {
    /**
     * @brief Computes a compile-time FNV-1a style hash of a string
     * @param str Pointer to the null-terminated string to hash
     * @param len Length of the string to hash
     * @return 64-bit hash value computed at compile time
     * @note Uses FNV-1a algorithm for fast, well-distributed hashing
     * @example
     * ```cpp
     * constexpr auto hash = const_hash("hello", 5);
     * ```
     */
    GHOSTSTR_CONSTEVAL std::uint64_t const_hash(const char* str, std::size_t len) noexcept {
        std::uint64_t hash = 0x14650FB0739D0383ULL;
        for (std::size_t i = 0; i < len; ++i) {
            hash ^= static_cast<std::uint64_t>(str[i]);
            hash *= 0x100000001B3ULL;
        }
        return hash;
    }

    /**
     * @brief Generates a compile-time seed value for encryption keys
     * @return 64-bit seed value based on compilation date/time or fixed constant
     * @note When GHOSTSTR_USE_TIME_SEED is enabled, uses __DATE__ and __TIME__ macros
     *       for varying encryption keys across builds. Otherwise returns fixed constant.
     * @example
     * ```cpp
     * constexpr auto seed = time_seed();
     * ```
     */
    GHOSTSTR_CONSTEVAL std::uint64_t time_seed() noexcept {
        if constexpr (GHOSTSTR_USE_TIME_SEED) {
            return const_hash(__DATE__ __TIME__, sizeof(__DATE__ __TIME__) - 1);
        }
        else {
            return 0x9E3779B97F4A7C15ULL;
        }
    }

    /**
     * @brief Builds a unique encryption key based on source location and context
     * @tparam FileHash Hash of the source file path
     * @tparam Line Source line number where the key is generated
     * @tparam Index Additional index parameter for uniqueness
     * @tparam Counter Compiler counter value for additional uniqueness
     * @return 64-bit encryption key unique to the call site
     * @note Combines multiple sources of entropy to ensure each string literal
     *       gets a unique encryption key, even within the same source location
     * @example
     * ```cpp
     * constexpr auto key = build_key<file_hash, __LINE__, 0, __COUNTER__>();
     * ```
     */
    template<std::uint64_t FileHash, int Line, std::size_t Index, int Counter>
    GHOSTSTR_CONSTEVAL std::uint64_t build_key() noexcept {
        std::uint64_t hash = 0x9E3779B97F4A7C15ULL
            ^ FileHash
            ^ (static_cast<std::uint64_t>(Line) * 0x100000001B3ULL)
            ^ (static_cast<std::uint64_t>(Index) * 0xBF58476D1CE4E5B9ULL)
            ^ (static_cast<std::uint64_t>(Counter) * 0x94D049BB133111EBULL)
            ^ time_seed();

        hash ^= hash >> 30;
        hash *= 0xBF58476D1CE4E5B9ULL;
        hash ^= hash >> 27;
        hash *= 0x94D049BB133111EBULL;
        hash ^= hash >> 31;

        return hash;
    }

    /**
     * @brief Performs position-dependent XOR encryption on a character
     * @tparam CharT Character type (char, wchar_t, char8_t, char16_t, char32_t)
     * @param c Character to encrypt/decrypt
     * @param key 64-bit encryption key
     * @param pos Position of character in string (affects key derivation)
     * @return Encrypted/decrypted character
     * @note Uses position-dependent key derivation to ensure identical characters
     *       at different positions encrypt to different values. Supports all
     *       standard character types with appropriate byte-wise operations.
     * @example
     * ```cpp
     * char encrypted = xor_encrypt_full('A', 0x123456789ABCDEF0ULL, 0);
     * char decrypted = xor_encrypt_full(encrypted, 0x123456789ABCDEF0ULL, 0);
     * ```
     */
    template<typename CharT>
    constexpr CharT xor_encrypt_full(CharT c, std::uint64_t key, std::size_t pos) noexcept {
        static_assert(std::is_integral_v<CharT>, "CharT must be an integral type");
        using UnsignedT = std::make_unsigned_t<CharT>;
        UnsignedT u = static_cast<UnsignedT>(c);

        if constexpr (sizeof(CharT) == 1) {
            std::uint64_t byte_key = key ^ (pos * 0x517CC1B727220A95ULL);
            std::uint8_t key_byte = static_cast<std::uint8_t>((byte_key >> ((pos & 7) * 8)) & 0xFF);
            u ^= static_cast<UnsignedT>(key_byte);
        }
        else if constexpr (sizeof(CharT) == 2) {
            std::uint64_t byte_key_0 = key ^ (pos * 0x517CC1B727220A95ULL);
            std::uint8_t key_byte_0 = static_cast<std::uint8_t>((byte_key_0 >> ((pos & 7) * 8)) & 0xFF);
            u ^= static_cast<UnsignedT>(key_byte_0);

            std::uint64_t byte_key_1 = key ^ ((pos * 0x517CC1B727220A95ULL) + 1);
            std::uint8_t key_byte_1 = static_cast<std::uint8_t>((byte_key_1 >> (((pos + 1) & 7) * 8)) & 0xFF);
            u ^= static_cast<UnsignedT>(static_cast<UnsignedT>(key_byte_1) << 8);
        }
        else if constexpr (sizeof(CharT) == 4) {
            std::uint64_t byte_key_0 = key ^ (pos * 0x517CC1B727220A95ULL);
            std::uint8_t key_byte_0 = static_cast<std::uint8_t>((byte_key_0 >> ((pos & 7) * 8)) & 0xFF);
            u ^= static_cast<UnsignedT>(key_byte_0);

            std::uint64_t byte_key_1 = key ^ ((pos * 0x517CC1B727220A95ULL) + 1);
            std::uint8_t key_byte_1 = static_cast<std::uint8_t>((byte_key_1 >> (((pos + 1) & 7) * 8)) & 0xFF);
            u ^= static_cast<UnsignedT>(static_cast<UnsignedT>(key_byte_1) << 8);

            std::uint64_t byte_key_2 = key ^ ((pos * 0x517CC1B727220A95ULL) + 2);
            std::uint8_t key_byte_2 = static_cast<std::uint8_t>((byte_key_2 >> (((pos + 2) & 7) * 8)) & 0xFF);
            u ^= static_cast<UnsignedT>(static_cast<UnsignedT>(key_byte_2) << 16);

            std::uint64_t byte_key_3 = key ^ ((pos * 0x517CC1B727220A95ULL) + 3);
            std::uint8_t key_byte_3 = static_cast<std::uint8_t>((byte_key_3 >> (((pos + 3) & 7) * 8)) & 0xFF);
            u ^= static_cast<UnsignedT>(static_cast<UnsignedT>(key_byte_3) << 24);
        }
        else {
            std::uint64_t byte_key = key ^ (pos * 0x517CC1B727220A95ULL);
            std::uint8_t key_byte = static_cast<std::uint8_t>((byte_key >> ((pos & 7) * 8)) & 0xFF);
            u ^= static_cast<UnsignedT>(key_byte);
        }

        return static_cast<CharT>(u);
    }

    /**
     * @brief Performs character substitution encryption for printable ASCII characters
     * @tparam CharT Character type
     * @param c Character to encrypt
     * @param key Encryption key used for substitution offset
     * @return Substituted character (if applicable) or original character
     * @note Only affects printable ASCII characters (32-126) when GHOSTSTR_ENABLE_SUBSTITUTION
     *       is enabled. Uses modular arithmetic to map characters within the printable range.
     * @example
     * ```cpp
     * char substituted = substitute_encrypt('A', 0x123456789ABCDEF0ULL);
     * ```
     */
    template<typename CharT>
    constexpr CharT substitute_encrypt(CharT c, std::uint64_t key) noexcept {
#if GHOSTSTR_ENABLE_SUBSTITUTION
        if constexpr (std::is_same_v<CharT, char>) {
            if (c >= 32 && c <= 126) {
                std::uint8_t offset = static_cast<std::uint8_t>((key >> 8) & 0x3F);
                return static_cast<CharT>(32 + ((c - 32 + offset) % 95));
            }
        }
#endif
        return c;
    }

    /**
     * @brief Creates a compiler memory barrier to prevent optimizations
     * @note Prevents the compiler from reordering memory operations across this point.
     *       Essential for security-sensitive operations to ensure memory is actually
     *       cleared and not optimized away. Implementation varies by compiler.
     * @example
     * ```cpp
     * // Clear sensitive data
     * memset(buffer, 0, size);
     * compiler_barrier(); // Ensure clearing is not optimized away
     * ```
     */
    GHOSTSTR_NOINLINE inline void compiler_barrier() noexcept {
#if defined(_MSC_VER)
        _ReadWriteBarrier();
#else
        asm volatile("" ::: "memory");
#endif
    }

    /**
     * @brief Securely zeros memory to prevent data recovery
     * @tparam T Type of data to zero
     * @param ptr Pointer to memory to clear
     * @param size Number of elements to clear
     * @note Uses volatile operations and compiler barrier to prevent optimization.
     *       Essential for clearing sensitive data like decrypted strings from memory.
     *       Cannot be optimized away by the compiler.
     * @example
     * ```cpp
     * char buffer[256];
     * // ... use buffer ...
     * secure_zero(buffer, 256); // Securely clear
     * ```
     */
    template<typename T>
    GHOSTSTR_NOINLINE void secure_zero(T* ptr, std::size_t size) noexcept {
        volatile std::uint8_t* vptr = reinterpret_cast<volatile std::uint8_t*>(ptr);
        for (std::size_t i = 0; i < size * sizeof(T); ++i) {
            vptr[i] = 0;
        }
        compiler_barrier();
    }

    /**
     * @brief A compile-time encrypted string class with secure runtime access
     * @tparam CharT Character type (char, wchar_t, char8_t, char16_t, char32_t)
     * @tparam N Size of the string including null terminator
     * @tparam Key1 First encryption key
     * @tparam Key2 Second encryption key
     * 
     * This class stores strings in an encrypted form at compile-time and provides
     * secure access methods for runtime decryption. The string is encrypted using
     * multiple layers: XOR encryption, optional character substitution, and final
     * XOR encryption. Memory is securely cleared after use to prevent data recovery.
     * 
     * The class provides RAII-based access through scoped_view to ensure automatic
     * cleanup of decrypted data, preventing sensitive strings from remaining in
     * memory longer than necessary.
     */
    template<typename CharT, std::size_t N, std::uint64_t Key1, std::uint64_t Key2>
    class obfuscated_string {
        static_assert(N > 0, "String length must be greater than 0");

    public:
        using value_type = CharT;         ///< Character type used by this string
        using size_type = std::size_t;    ///< Type used for sizes and indices
        using pointer = value_type*;      ///< Pointer to mutable character type
        using const_pointer = const value_type*; ///< Pointer to immutable character type

        /**
         * @brief RAII wrapper for secure temporary access to decrypted string data
         * 
         * Provides safe, temporary access to the decrypted string content. The buffer
         * is automatically and securely cleared when the scoped_view is destroyed,
         * ensuring sensitive data doesn't remain in memory. Cannot be copied or moved
         * to prevent accidental data leakage.
         */
        struct scoped_view {
            std::array<CharT, N> buffer; ///< Decrypted string buffer
            std::basic_string_view<CharT> view; ///< String view of the decrypted data

            /**
             * @brief Constructs scoped view by decrypting the obfuscated string
             * @param self Reference to the obfuscated string to decrypt
             */
            explicit scoped_view(const obfuscated_string& self)
                : buffer(self.decrypt_copy()), view(buffer.data(), N > 0 ? N - 1 : 0) {
            }

            /**
             * @brief Destructor that securely clears the decrypted buffer
             */
            ~scoped_view() {
                secure_zero(buffer.data(), buffer.size());
            }

            scoped_view(const scoped_view&) = delete; ///< No copy constructor
            scoped_view& operator=(const scoped_view&) = delete; ///< No copy assignment
            scoped_view(scoped_view&&) = delete; ///< No move constructor
            scoped_view& operator=(scoped_view&&) = delete; ///< No move assignment

            /**
             * @brief Gets pointer to the decrypted string data
             * @return Pointer to null-terminated string data
             */
            const_pointer data() const noexcept { return view.data(); }
            
            /**
             * @brief Gets C-style string pointer
             * @return Pointer to null-terminated string data
             */
            const_pointer c_str() const noexcept { return view.data(); }
            
            /**
             * @brief Gets the length of the string
             * @return Number of characters (excluding null terminator)
             */
            std::size_t size() const noexcept { return view.size(); }
            
            /**
             * @brief Implicit conversion to string_view
             * @return String view of the decrypted data
             */
            operator std::basic_string_view<CharT>() const noexcept { return view; }
        };

        /**
         * @brief Holder for C-style string access with automatic cleanup
         * 
         * Combines scoped_view with convenient C-string access. Maintains
         * the decrypted data and provides direct pointer access while ensuring
         * secure cleanup when destroyed.
         */
        struct c_str_holder {
            scoped_view sv;         ///< Underlying scoped view
            const CharT* ptr;       ///< Pointer to C-string data
            std::size_t len;        ///< Length of the string

            /**
             * @brief Constructs holder with decrypted string access
             * @param self Reference to the obfuscated string
             */
            explicit c_str_holder(const obfuscated_string& self)
                : sv(self.scoped()), ptr(sv.data()), len(sv.size()) {
            }

            c_str_holder(const c_str_holder&) = delete; ///< No copy constructor
            c_str_holder& operator=(const c_str_holder&) = delete; ///< No copy assignment
            c_str_holder(c_str_holder&&) = delete; ///< No move constructor
            c_str_holder& operator=(c_str_holder&&) = delete; ///< No move assignment
        };

        /**
         * @brief Creates a C-string holder for temporary access
         * @return RAII holder with C-string access
         * @note The returned holder must be kept alive for the duration of string access
         * @example
         * ```cpp
         * auto holder = obfuscated.c_str_scoped();
         * printf("%s", holder.ptr); // Safe access
         * // holder automatically cleans up when destroyed
         * ```
         */
        c_str_holder c_str_scoped() const noexcept {
            return c_str_holder{ *this };
        }

    private:
        std::array<CharT, N> storage_; ///< Encrypted string storage

        /**
         * @brief Encrypts a string literal at compile-time
         * @param str Pointer to the string literal to encrypt
         * @return Array containing the encrypted string data
         * @note Uses triple-layer encryption: XOR, substitution, final XOR.
         *       This method is called at compile-time to encrypt the string literal.
         */
        GHOSTSTR_CONSTEVAL static std::array<CharT, N> encrypt_string(const CharT* str) noexcept {
            std::array<CharT, N> result{};
            for (size_type i = 0; i < N - 1; ++i) {
                CharT c = str[i];

                c = xor_encrypt_full(c, Key1, i);
                c = substitute_encrypt(c, Key2);

                std::uint64_t final_key = Key1 ^ Key2 ^ (i * 0x9E3779B97F4A7C15ULL);
                c = xor_encrypt_full(c, final_key, i);

                result[i] = c;
            }
            result[N - 1] = static_cast<CharT>(0);
            return result;
        }

    public:
        /**
         * @brief Constructs obfuscated string from string literal at compile-time
         * @param str String literal to encrypt and store
         * @note This constructor encrypts the string at compile-time using the
         *       template parameters Key1 and Key2. The original string data is
         *       not stored in the binary.
         * @example
         * ```cpp
         * constexpr auto secret = obfuscated_string<char, 6, key1, key2>("hello");
         * ```
         */
        GHOSTSTR_CONSTEVAL obfuscated_string(const CharT(&str)[N]) noexcept
            : storage_(encrypt_string(str)) {
        }

        /**
         * @brief Gets the length of the string (excluding null terminator)
         * @return Number of characters in the string
         */
        GHOSTSTR_CONSTEVAL size_type size() const noexcept { return N > 0 ? N - 1 : 0; }
        
        /**
         * @brief Gets the length of the string (alias for size())
         * @return Number of characters in the string
         */
        GHOSTSTR_CONSTEVAL size_type length() const noexcept { return size(); }

        /**
         * @brief Decrypts the string and returns a copy in a new array
         * @return Array containing the decrypted string data
         * @note The returned array contains the decrypted data and should be
         *       securely cleared after use. Consider using scoped() for automatic cleanup.
         * @example
         * ```cpp
         * auto decrypted = obfuscated.decrypt_copy();
         * // Use decrypted.data()...
         * secure_zero(decrypted.data(), decrypted.size()); // Manual cleanup
         * ```
         */
        GHOSTSTR_NOINLINE std::array<CharT, N> decrypt_copy() const noexcept {
            std::array<CharT, N> result{};

            for (size_type i = 0; i < N - 1; ++i) {
                CharT c = storage_[i];

                std::uint64_t final_key = Key1 ^ Key2 ^ (i * 0x9E3779B97F4A7C15ULL);
                c = xor_encrypt_full(c, final_key, i);

#if GHOSTSTR_ENABLE_SUBSTITUTION
                if constexpr (std::is_same_v<CharT, char>) {
                    if (c >= 32 && c <= 126) {
                        std::uint8_t offset = static_cast<std::uint8_t>((Key2 >> 8) & 0x3F);
                        c = static_cast<CharT>(32 + ((c - 32 + 95 - (offset % 95)) % 95));
                    }
                }
#endif

                c = xor_encrypt_full(c, Key1, i);

                result[i] = c;
            }
            result[N - 1] = static_cast<CharT>(0);

            compiler_barrier();
            return result;
        }

        /**
         * @brief Creates a scoped view for safe temporary access to decrypted data
         * @return RAII scoped view that automatically clears data on destruction
         * @note Preferred method for accessing decrypted string data as it ensures
         *       automatic secure cleanup when the view goes out of scope.
         * @example
         * ```cpp
         * {
         *     auto view = obfuscated.scoped();
         *     printf("%s", view.c_str()); // Safe access
         * } // Automatically cleared here
         * ```
         */
        scoped_view scoped() const noexcept {
            return scoped_view(*this);
        }

        /**
         * @brief Converts the obfuscated string to a standard string
         * @return Standard string containing the decrypted data
         * @note The returned string contains a copy of the decrypted data.
         *       Consider the security implications of having unencrypted data
         *       in a standard string which may not be securely cleared.
         * @example
         * ```cpp
         * std::string plain = obfuscated.str();
         * ```
         */
        std::basic_string<CharT> str() const {
            auto tmp = decrypt_copy();
            return std::basic_string<CharT>(tmp.data(), size());
        }

        /**
         * @brief Securely clears the encrypted storage
         * @note Overwrites the encrypted data with zeros. After calling this,
         *       the obfuscated string cannot be decrypted anymore.
         * @example
         * ```cpp
         * obfuscated.clear(); // Permanently destroy the encrypted data
         * ```
         */
        GHOSTSTR_NOINLINE void clear() noexcept {
            secure_zero(storage_.data(), storage_.size());
        }

        /**
         * @brief Compares this obfuscated string with another obfuscated string
         * @tparam C2 Character type of the other string
         * @tparam M Size of the other string
         * @tparam K1b First key of the other string
         * @tparam K2b Second key of the other string
         * @param other The other obfuscated string to compare with
         * @return true if the decrypted contents are equal, false otherwise
         * @note Performs constant-time comparison after decryption to prevent
         *       timing attacks. Returns false immediately if character types differ.
         * @example
         * ```cpp
         * auto str1 = ghostStr("hello");
         * auto str2 = ghostStr("hello");
         * bool same = str1.equals(str2); // true
         * ```
         */
        template<typename C2, std::size_t M, std::uint64_t K1b, std::uint64_t K2b>
        bool equals(const obfuscated_string<C2, M, K1b, K2b>& other) const noexcept {
            if constexpr (!std::is_same_v<CharT, C2>) {
                return false;
            }
            else {
                if (this->size() != other.size()) return false;
                auto a = this->decrypt_copy();
                auto b = other.decrypt_copy();
                std::basic_string_view<CharT> view_a(a.data(), this->size());
                std::basic_string_view<CharT> view_b(b.data(), other.size());
                return view_a == view_b;
            }
        }

        /**
         * @brief Equality operator for comparing with another obfuscated string
         * @param other The other obfuscated string to compare with
         * @return true if the decrypted contents are equal, false otherwise
         * @note Uses the equals() method for secure comparison
         * @example
         * ```cpp
         * auto str1 = ghostStr("hello");
         * auto str2 = ghostStr("hello");
         * bool same = (str1 == str2); // true
         * ```
         */
        bool operator==(const obfuscated_string& other) const noexcept {
            return equals(other);
        }

        /**
         * @brief Equality operator for comparing with a C-string
         * @param str Null-terminated C-string to compare with
         * @return true if the decrypted content equals the C-string, false otherwise
         * @note Decrypts the obfuscated string for comparison
         * @example
         * ```cpp
         * auto secret = ghostStr("password");
         * bool match = (secret == "password"); // true
         * ```
         */
        bool operator==(const CharT* str) const noexcept {
            auto decrypted = decrypt_copy();
            return std::basic_string_view<CharT>(decrypted.data(), size()) == str;
        }

        /**
         * @brief Equality operator for comparing with a string view
         * @param sv String view to compare with
         * @return true if the decrypted content equals the string view, false otherwise
         * @note Decrypts the obfuscated string for comparison
         * @example
         * ```cpp
         * auto secret = ghostStr("data");
         * std::string_view sv = "data";
         * bool match = (secret == sv); // true
         * ```
         */
        bool operator==(std::basic_string_view<CharT> sv) const noexcept {
            auto decrypted = decrypt_copy();
            return std::basic_string_view<CharT>(decrypted.data(), size()) == sv;
        }
    };

    /**
     * @brief Creates an obfuscated string with specified encryption keys
     * @tparam CharT Character type of the string literal
     * @tparam N Size of the string literal including null terminator
     * @tparam K1 First encryption key
     * @tparam K2 Second encryption key
     * @param str String literal to obfuscate
     * @return obfuscated_string instance with the encrypted string
     * @note This function is typically used by macros rather than called directly.
     *       Prefer using the ghostStr() macros for automatic key generation.
     * @example
     * ```cpp
     * constexpr auto secret = make_obfuscated_with_keys<char, 6, 0x123, 0x456>("hello");
     * ```
     */
    template<typename CharT, std::size_t N, std::uint64_t K1, std::uint64_t K2>
    GHOSTSTR_CONSTEVAL auto make_obfuscated_with_keys(const CharT(&str)[N]) noexcept {
        return obfuscated_string<CharT, N, K1, K2>(str);
    }

}

/**
 * @brief Internal macro for creating obfuscated strings with site-specific keys
 * @param STR_LIT String literal to obfuscate
 * @param IDX Index for key differentiation
 * @note This macro generates unique encryption keys based on file path, line number,
 *       index, and compiler counter. Used internally by the public ghostStr macros.
 */
#define GHOSTSTR_MAKE_WITH_SITE(STR_LIT, IDX)                                                    \
    (::ghoststr::make_obfuscated_with_keys<                                                      \
        std::remove_cv_t<std::remove_reference_t<decltype(*(STR_LIT))>>,                         \
        sizeof(STR_LIT),                                                                         \
        ::ghoststr::build_key< ::ghoststr::const_hash(__FILE__, sizeof(__FILE__) - 1),           \
                               __LINE__, (IDX), __COUNTER__ >(),                                 \
        ::ghoststr::build_key< ::ghoststr::const_hash(__FILE__, sizeof(__FILE__) - 1),           \
                               __LINE__, (IDX) + 0x42, __COUNTER__ >()                           \
    >(STR_LIT))

/**
 * @brief Creates an obfuscated char string with automatic key generation
 * @param str String literal to obfuscate (char)
 * @return obfuscated_string instance
 * @note Primary macro for creating obfuscated strings. Keys are automatically
 *       generated based on source location for maximum security.
 * @example
 * ```cpp
 * auto secret = ghostStr("sensitive data");
 * auto view = secret.scoped();
 * printf("Secret: %s\n", view.c_str());
 * ```
 */
#define ghostStr(str)      GHOSTSTR_MAKE_WITH_SITE(str, 0)

/**
 * @brief Creates an obfuscated wide string with automatic key generation
 * @param str String literal to obfuscate (will be prefixed with L)
 * @return obfuscated_string instance for wchar_t
 * @example
 * ```cpp
 * auto secret = ghostStr_w("sensitive data");
 * ```
 */
#define ghostStr_w(str)    GHOSTSTR_MAKE_WITH_SITE(L##str, 1)

/**
 * @brief Creates an obfuscated UTF-8 string with automatic key generation
 * @param str String literal to obfuscate (will be prefixed with u8)
 * @return obfuscated_string instance for char8_t
 * @example
 * ```cpp
 * auto secret = ghostStr_u8("sensitive data");
 * ```
 */
#define ghostStr_u8(str)   GHOSTSTR_MAKE_WITH_SITE(u8##str, 2)

/**
 * @brief Creates an obfuscated UTF-16 string with automatic key generation
 * @param str String literal to obfuscate (will be prefixed with u)
 * @return obfuscated_string instance for char16_t
 * @example
 * ```cpp
 * auto secret = ghostStr_u16("sensitive data");
 * ```
 */
#define ghostStr_u16(str)  GHOSTSTR_MAKE_WITH_SITE(u##str, 3)

/**
 * @brief Creates an obfuscated UTF-32 string with automatic key generation
 * @param str String literal to obfuscate (will be prefixed with U)
 * @return obfuscated_string instance for char32_t
 * @example
 * ```cpp
 * auto secret = ghostStr_u32("sensitive data");
 * ```
 */
#define ghostStr_u32(str)  GHOSTSTR_MAKE_WITH_SITE(U##str, 4)

/**
 * @brief Creates an obfuscated char string with manually specified keys
 * @param str String literal to obfuscate
 * @param k1 First encryption key
 * @param k2 Second encryption key
 * @return obfuscated_string instance
 * @note Use this when you need deterministic encryption keys across builds
 * @example
 * ```cpp
 * auto secret = ghostStr_key("data", 0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL);
 * ```
 */
#define ghostStr_key(str, k1, k2) \
    (::ghoststr::obfuscated_string<char, sizeof(str), k1, k2>(str))

/**
 * @brief Creates an obfuscated wide string with manually specified keys
 * @param str String literal to obfuscate (will be prefixed with L)
 * @param k1 First encryption key
 * @param k2 Second encryption key
 * @return obfuscated_string instance for wchar_t
 */
#define ghostStr_key_w(str, k1, k2) \
    (::ghoststr::obfuscated_string<wchar_t, sizeof(L##str)/sizeof(wchar_t), k1, k2>(L##str))

/**
 * @brief Creates an obfuscated UTF-8 string with manually specified keys
 * @param str String literal to obfuscate (will be prefixed with u8)
 * @param k1 First encryption key
 * @param k2 Second encryption key
 * @return obfuscated_string instance for char8_t
 */
#define ghostStr_key_u8(str, k1, k2) \
    (::ghoststr::obfuscated_string<char8_t, sizeof(u8##str)/sizeof(char8_t), k1, k2>(u8##str))

/**
 * @brief Creates an obfuscated UTF-16 string with manually specified keys
 * @param str String literal to obfuscate (will be prefixed with u)
 * @param k1 First encryption key
 * @param k2 Second encryption key
 * @return obfuscated_string instance for char16_t
 */
#define ghostStr_key_u16(str, k1, k2) \
    (::ghoststr::obfuscated_string<char16_t, sizeof(u##str)/sizeof(char16_t), k1, k2>(u##str))

/**
 * @brief Creates an obfuscated UTF-32 string with manually specified keys
 * @param str String literal to obfuscate (will be prefixed with U)
 * @param k1 First encryption key
 * @param k2 Second encryption key
 * @return obfuscated_string instance for char32_t
 */
#define ghostStr_key_u32(str, k1, k2) \
    (::ghoststr::obfuscated_string<char32_t, sizeof(U##str)/sizeof(char32_t), k1, k2>(U##str))
