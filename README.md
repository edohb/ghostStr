# ghostStr

> A tiny, header-only C++20 **compile-time string obfuscation** library.

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage-examples">Examples</a> •
  <a href="#api">API</a> •
  <a href="#build--integration">Build</a> •
  <a href="#security-notes">Security</a> •
  <a href="#faq">FAQ</a> •
  <a href="#license">License</a>
</p>

---

## Features

* ✅ **Compile-time encryption** via `consteval` — plaintext never lands in your binary
* 🔐 **Multi-layer scheme**: position-dependent XOR → optional substitution → final XOR
* 🧩 **All char types**: `char`, `wchar_t`, `char8_t`, `char16_t`, `char32_t`
* 🗝️ **Automatic per-site keys** derived from file path, line, index, `__COUNTER__`, and an optional time seed
* 🧹 **RAII access + secure zero**: decrypted bytes are wiped when the view goes out of scope
* 🧱 Header-only, no deps. Works with MSVC / Clang / GCC on C++20+

---

## Demo

```cpp
#include <cstdio>
#include "ghoststr.hpp"

int main() {
    auto s = ghostStr("This is an encrypted string!");
    {
        auto view = s.scoped();                 // RAII-decrypted view
        std::printf("Decrypted: %s\n", view.c_str());
    }                                           // securely zeroed here
}
```

Output (runtime):

```
Decrypted: This is an encrypted string!
```

> In your binary, the plaintext never appears; only encrypted bytes are stored.

---

## Table of Contents

* [Install](#install)
* [Quick Start](#quick-start)
* [Configuration](#configuration)
* [API](#api)
* [Build & Integration](#build--integration)
* [License](#license)

---

## Install

This is a single header. Drop it in and include it:

```
your_project/
└─ include/
   └─ ghoststr.hpp
```

```cpp
#include "ghoststr.hpp"
```

Requirements:

* **C++20**: `/std:c++20` (MSVC) or `-std=c++20` (GCC/Clang)

---

## Quick Start

Create obfuscated strings with automatic, per-site keys:

```cpp
auto a = ghostStr("user=admin");
auto b = ghostStr_w("hello world");     // wchar_t
auto c = ghostStr_u8("UTF-8 ✓");
auto d = ghostStr_u16(u"こんにちは");
auto e = ghostStr_u32(U"𠮷野家");
```

Read safely using a scoped view (auto-cleans):

```cpp
{
    auto v = a.scoped();
    // v.data() / v.c_str() are valid until scope ends
}
```

If you need a temporary C-style pointer:

```cpp
auto holder = a.c_str_scoped();
use(holder.ptr, holder.len);    // valid while 'holder' lives
```

Compare contents:

```cpp
bool same = (a == "user=admin");    // compares to C-string
```

Destroy encrypted storage permanently:

```cpp
a.clear();  // overwrites encrypted bytes; cannot be recovered
```

---

## Configuration

These can be defined **before** including the header.

| Macro                          | Default | Description                                                                                           |
| ------------------------------ | :-----: | ----------------------------------------------------------------------------------------------------- |
| `GHOSTSTR_USE_TIME_SEED`       |   `0`   | If `1`, per-build seed derives from `__DATE__`+`__TIME__`. Produces different ciphertext every build. |
| `GHOSTSTR_ENABLE_SUBSTITUTION` |   `1`   | Enables printable-ASCII substitution layer for `char` strings.                                        |

Example:

```cpp
#define GHOSTSTR_USE_TIME_SEED 1
#define GHOSTSTR_ENABLE_SUBSTITUTION 1
#include "ghoststr.hpp"
```

---

## API

### Macros (automatic key generation)

```cpp
ghostStr("text")        // char
ghostStr_w("text")      // wchar_t
ghostStr_u8("text")     // char8_t
ghostStr_u16("text")    // char16_t
ghostStr_u32("text")    // char32_t
```

### Macros (manual keys, deterministic)

```cpp
ghostStr_key("text", k1, k2)
ghostStr_key_w("text", k1, k2)
ghostStr_key_u8("text", k1, k2)
ghostStr_key_u16("text", k1, k2)
ghostStr_key_u32("text", k1, k2)
```

### Type

```cpp
template<
  typename CharT,
  std::size_t N,
  std::uint64_t Key1,
  std::uint64_t Key2
>
class ghoststr::obfuscated_string {
public:
    using value_type    = CharT;
    using size_type     = std::size_t;

    // Compile-time size (no terminator)
    consteval size_type size()   const noexcept;
    consteval size_type length() const noexcept;

    // Decrypt -> copy (caller should zero if kept)
    std::array<CharT, N> decrypt_copy() const noexcept;

    // Preferred RAII access (auto zero on dtor)
    struct scoped_view {
        const CharT* data() const noexcept;
        const CharT* c_str() const noexcept;
        std::size_t  size() const noexcept;
        operator std::basic_string_view<CharT>() const noexcept;
    };
    scoped_view scoped() const noexcept;

    // C-string convenience RAII wrapper
    struct c_str_holder {
        const CharT* ptr;
        std::size_t  len;
    };
    c_str_holder c_str_scoped() const noexcept;

    // Convenience (beware of plaintext lifetime)
    std::basic_string<CharT> str() const;

    // Permanently destroy encrypted storage
    void clear() noexcept;

    // Comparisons (decrypts internally)
    bool operator==(const obfuscated_string&) const noexcept;
    bool operator==(const CharT*) const noexcept;
    bool operator==(std::basic_string_view<CharT>) const noexcept;
};
```

---

## Build & Integration

### Compiler flags

* **MSVC**: `/std:c++20 /O2` (or `/Ox`)
* **Clang/GCC**: `-std=c++20 -O2` (or `-O3`)

No extra libraries required.

---

## Security Notes

* **Plaintext lifetime**: prefer `scoped()` / `c_str_scoped()`; they **securely zero** memory on destruction. Avoid `str()` unless necessary.
* **Different every call site**: automatic keys fold in file path, line, index, `__COUNTER__`, and optional time seed, so even identical literals encrypt differently across sites and builds.
* **Wide/UTF strings**: 16/32-bit types use byte-wise XOR with position-dependent per-byte keys.

---

## Minimal Example

```cpp
#include <cstdio>
#include "ghoststr.hpp"

int main() {
    auto string = ghostStr("This is an encrypted string!");
    {
        auto view = string.scoped();
        printf("Decrypted String: %s\n", view.data());
    }

    return 0;
}
```