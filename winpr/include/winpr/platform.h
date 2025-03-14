/**
 * WinPR: Windows Portable Runtime
 * Platform-Specific Definitions
 *
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WINPR_PLATFORM_H
#define WINPR_PLATFORM_H

#include <stdlib.h>

/* MSVC only defines _Pragma if you compile with /std:c11 with no extensions
 * see
 * https://learn.microsoft.com/en-us/cpp/preprocessor/pragma-directives-and-the-pragma-keyword?view=msvc-170#the-pragma-preprocessing-operator
 */
#if !defined(_MSC_VER)
#define WINPR_DO_PRAGMA(x) _Pragma(#x)
#else
#define WINPR_DO_PRAGMA(x) __pragma(#x)
#endif

/* COVERITY_BUILD must be defined by build system */
#if !defined(COVERITY_BUILD)
#define WINPR_DO_COVERITY_PRAGMA(x)
#else
#define WINPR_DO_COVERITY_PRAGMA(x) WINPR_DO_PRAGMA(x)
#endif

#if defined(__GNUC__)
#define WINPR_PRAGMA_WARNING(msg) WINPR_DO_PRAGMA(GCC warning #msg)
#elif defined(__clang__)
#define WINPR_PRAGMA_WARNING(msg) WINPR_DO_PRAGMA(GCC warning #msg)
#elif defined(_MSC_VER) && (_MSC_VER >= 1920)
#define WINPR_PRAGMA_WARNING(msg) WINPR_DO_PRAGMA(message \x28 #msg \x29)
#else
#define WINPR_PRAGMA_WARNING(msg)
#endif

// C99 related macros
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
#define WINPR_RESTRICT restrict
#elif defined(_MSC_VER) && _MSC_VER >= 1900
#define WINPR_RESTRICT __restrict
#else
#define WINPR_RESTRICT
#endif

// C23 related macros
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 202311L)
#define WINPR_FALLTHROUGH \
	(void)0;              \
	[[fallthrough]];
#elif defined(__clang__)
#define WINPR_FALLTHROUGH \
	(void)0;              \
	__attribute__((fallthrough));
#elif defined(__GNUC__) && (__GNUC__ >= 7)
#define WINPR_FALLTHROUGH \
	(void)0;              \
	__attribute__((fallthrough));
#else
#define WINPR_FALLTHROUGH (void)0;
#endif

#if defined(__clang__)
#define WINPR_PRAGMA_DIAG_PUSH WINPR_DO_PRAGMA(clang diagnostic push)
#define WINPR_PRAGMA_DIAG_IGNORED_OVERLENGTH_STRINGS \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Woverlength-strings") /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_QUALIFIERS
/* unsupported by clang WINPR_DO_PRAGMA(clang diagnostic ignored "-Wdiscarded-qualifiers") */ /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_PEDANTIC WINPR_DO_PRAGMA(clang diagnostic ignored "-Wpedantic")
#define WINPR_PRAGMA_DIAG_IGNORED_MISSING_PROTOTYPES \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wmissing-prototypes")
#define WINPR_PRAGMA_DIAG_IGNORED_STRICT_PROTOTYPES \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wstrict-prototypes")
#define WINPR_PRAGMA_DIAG_IGNORED_RESERVED_ID_MACRO \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wreserved-id-macro")
#define WINPR_PRAGMA_DIAG_IGNORED_UNUSED_MACRO \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wunused-macros")
#define WINPR_PRAGMA_DIAG_IGNORED_UNKNOWN_PRAGMAS \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wunknown-pragmas") /** @since version 3.10.0 */

#if __clang_major__ >= 13
#define WINPR_PRAGMA_DIAG_IGNORED_RESERVED_IDENTIFIER \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wreserved-identifier")
#else
#define WINPR_PRAGMA_DIAG_IGNORED_RESERVED_IDENTIFIER
#endif

#define WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Watomic-implicit-seq-cst")
#define WINPR_PRAGMA_DIAG_IGNORED_UNUSED_CONST_VAR \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wunused-const-variable")
#define WINPR_PRAGMA_DIAG_IGNORED_FORMAT_SECURITY \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wformat-security")
#define WINPR_PRAGMA_DIAG_TAUTOLOGICAL_CONSTANT_OUT_OF_RANGE_COMPARE           \
	WINPR_DO_PRAGMA(clang diagnostic ignored                                   \
	                "-Wtautological-constant-out-of-range-compare") /** @since \
	                                                               version     \
	                                                               3.9.0       \
	                                                             */
#if __clang_major__ >= 12
#define WINPR_PRAGMA_DIAG_TAUTOLOGICAL_VALUE_RANGE_COMPARE           \
	WINPR_DO_PRAGMA(clang diagnostic ignored                         \
	                "-Wtautological-value-range-compare") /** @since \
	                                                             version 3.10.0 */
#else
#define WINPR_PRAGMA_DIAG_TAUTOLOGICAL_VALUE_RANGE_COMPARE
#endif

#define WINPR_PRAGMA_DIAG_IGNORED_FORMAT_NONLITERAL \
	WINPR_DO_PRAGMA(clang diagnostic ignored "-Wformat-nonliteral") /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC /** @since version 3.3.0 */ /* not supported \
    WINPR_DO_PRAGMA(clang diagnostic ignored "-Wmismatched-dealloc") */
#define WINPR_PRAGMA_DIAG_POP WINPR_DO_PRAGMA(clang diagnostic pop)
#define WINPR_PRAGMA_UNROLL_LOOP                                                          \
	_Pragma("clang loop vectorize_width(8) interleave_count(8)") /** @since version 3.6.0 \
	                                                              */
#elif defined(__GNUC__)
#define WINPR_PRAGMA_DIAG_PUSH WINPR_DO_PRAGMA(GCC diagnostic push)
#define WINPR_PRAGMA_DIAG_IGNORED_OVERLENGTH_STRINGS \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Woverlength-strings") /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_QUALIFIERS \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wdiscarded-qualifiers") /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_PEDANTIC WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wpedantic")
#define WINPR_PRAGMA_DIAG_IGNORED_MISSING_PROTOTYPES \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wmissing-prototypes")
#define WINPR_PRAGMA_DIAG_IGNORED_STRICT_PROTOTYPES \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wstrict-prototypes")
#define WINPR_PRAGMA_DIAG_IGNORED_RESERVED_ID_MACRO /* not supported WINPR_DO_PRAGMA(GCC         \
                                                       diagnostic ignored "-Wreserved-id-macro") \
                                                     */
#define WINPR_PRAGMA_DIAG_IGNORED_UNUSED_MACRO \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wunused-macros")
#define WINPR_PRAGMA_DIAG_IGNORED_UNKNOWN_PRAGMAS \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wunknown-pragmas") /** @since version 3.10.0 */

#define WINPR_PRAGMA_DIAG_IGNORED_RESERVED_IDENTIFIER
/* not supported	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wreserved-identifier") */
#define WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST /* not supported	WINPR_DO_PRAGMA(GCC diagnostic \
                                                    ignored                                      \
                                                    "-Watomic-implicit-seq-cst") */
#define WINPR_PRAGMA_DIAG_IGNORED_UNUSED_CONST_VAR \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wunused-const-variable")
#define WINPR_PRAGMA_DIAG_IGNORED_FORMAT_SECURITY \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wformat-security")
#define WINPR_PRAGMA_DIAG_TAUTOLOGICAL_CONSTANT_OUT_OF_RANGE_COMPARE /* not supported
    WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wtautological-constant-out-of-range-compare") */ /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_TAUTOLOGICAL_VALUE_RANGE_COMPARE /* not supported
    WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wtautological-value-range-compare") */ /** @since version 3.10.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_FORMAT_NONLITERAL \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wformat-nonliteral") /** @since version 3.9.0 */
#if __GNUC__ >= 11
#define WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC \
	WINPR_DO_PRAGMA(GCC diagnostic ignored "-Wmismatched-dealloc") /** @since version 3.3.0 */
#else
#define WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC
#endif
#define WINPR_PRAGMA_DIAG_POP WINPR_DO_PRAGMA(GCC diagnostic pop)
#define WINPR_PRAGMA_UNROLL_LOOP \
	WINPR_DO_PRAGMA(GCC unroll 8) WINPR_DO_PRAGMA(GCC ivdep) /** @since version 3.6.0 */
#else
#define WINPR_PRAGMA_DIAG_PUSH
#define WINPR_PRAGMA_DIAG_IGNORED_PEDANTIC
#define WINPR_PRAGMA_DIAG_IGNORED_QUALIFIERS         /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_OVERLENGTH_STRINGS /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_MISSING_PROTOTYPES
#define WINPR_PRAGMA_DIAG_IGNORED_STRICT_PROTOTYPES
#define WINPR_PRAGMA_DIAG_IGNORED_RESERVED_ID_MACRO
#define WINPR_PRAGMA_DIAG_IGNORED_UNUSED_MACRO
#define WINPR_PRAGMA_DIAG_IGNORED_UNKNOWN_PRAGMAS /** @since version 3.10.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_RESERVED_IDENTIFIER
#define WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST
#define WINPR_PRAGMA_DIAG_IGNORED_UNUSED_CONST_VAR
#define WINPR_PRAGMA_DIAG_IGNORED_FORMAT_SECURITY
#define WINPR_PRAGMA_DIAG_TAUTOLOGICAL_CONSTANT_OUT_OF_RANGE_COMPARE /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_TAUTOLOGICAL_VALUE_RANGE_COMPARE           /** @since version 3.10.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_FORMAT_NONLITERAL  /** @since version 3.9.0 */
#define WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC /** @since version 3.3.0 */
#define WINPR_PRAGMA_DIAG_POP
#define WINPR_PRAGMA_UNROLL_LOOP /** @since version 3.6.0 */
#endif

#if defined(MSVC)
#undef WINPR_PRAGMA_UNROLL_LOOP
#define WINPR_PRAGMA_UNROLL_LOOP WINPR_DO_PRAGMA(loop(ivdep)) /** @since version 3.6.0 */
#endif

WINPR_PRAGMA_DIAG_PUSH

WINPR_PRAGMA_DIAG_IGNORED_RESERVED_ID_MACRO

/*
 * Processor Architectures:
 * http://sourceforge.net/p/predef/wiki/Architectures/
 *
 * Visual Studio Predefined Macros:
 * http://msdn.microsoft.com/en-ca/library/vstudio/b0084kay.aspx
 */

/* Intel x86 (_M_IX86) */

#if defined(i386) || defined(__i386) || defined(__i386__) || defined(__i486__) ||            \
    defined(__i586__) || defined(__i686__) || defined(__X86__) || defined(_X86_) ||          \
    defined(__I86__) || defined(__IA32__) || defined(__THW_INTEL__) || defined(__INTEL__) || \
    defined(_M_IX86)
#ifndef _M_IX86
#define _M_IX86 1
#endif
#endif

/* AMD64 (_M_AMD64) */

#if defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || \
    defined(_M_X64)
#ifndef _M_AMD64
#define _M_AMD64 1
#endif
#endif

/* Intel ia64 */
#if defined(__ia64) || defined(__ia64__) || defined(_M_IA64)
#ifndef _M_IA64
#define _M_IA64 1
#endif
#endif

/* Intel x86 or AMD64 (_M_IX86_AMD64) */

#if defined(_M_IX86) || defined(_M_AMD64)
#ifndef _M_IX86_AMD64
#define _M_IX86_AMD64 1
#endif
#endif

/* ARM (_M_ARM) */

#if defined(__arm__) || defined(__thumb__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB)
#ifndef _M_ARM
#define _M_ARM 1
#endif
#endif

/* ARM64 (_M_ARM64) */

#if defined(__aarch64__)
#ifndef _M_ARM64
#define _M_ARM64 1
#endif
#endif

/* MIPS (_M_MIPS) */

#if defined(mips) || defined(__mips) || defined(__mips__) || defined(__MIPS__)
#ifndef _M_MIPS
#define _M_MIPS 1
#endif
#endif

/* MIPS64 (_M_MIPS64) */

#if defined(mips64) || defined(__mips64) || defined(__mips64__) || defined(__MIPS64__)
#ifndef _M_MIPS64
#define _M_MIPS64 1
#endif
#endif

/* PowerPC (_M_PPC) */

#if defined(__ppc__) || defined(__powerpc) || defined(__powerpc__) || defined(__POWERPC__) || \
    defined(_ARCH_PPC)
#ifndef _M_PPC
#define _M_PPC 1
#endif
#endif

/* Intel Itanium (_M_IA64) */

#if defined(__ia64) || defined(__ia64__) || defined(_IA64) || defined(__IA64__)
#ifndef _M_IA64
#define _M_IA64 1
#endif
#endif

/* Alpha (_M_ALPHA) */

#if defined(__alpha) || defined(__alpha__)
#ifndef _M_ALPHA
#define _M_ALPHA 1
#endif
#endif

/* SPARC (_M_SPARC) */

#if defined(__sparc) || defined(__sparc__)
#ifndef _M_SPARC
#define _M_SPARC 1
#endif
#endif

/* E2K (_M_E2K) */

#if defined(__e2k__)
#ifndef _M_E2K
#define _M_E2K 1
#endif
#endif

/**
 * Operating Systems:
 * http://sourceforge.net/p/predef/wiki/OperatingSystems/
 */

/* Windows (_WIN32) */

/* WinRT (_WINRT) */

#if defined(WINAPI_FAMILY)
#if (WINAPI_FAMILY == WINAPI_FAMILY_APP)
#ifndef _WINRT
#define _WINRT 1
#endif
#endif
#endif

#if defined(__cplusplus_winrt)
#ifndef _WINRT
#define _WINRT 1
#endif
#endif

/* Linux (__linux__) */

#if defined(linux) || defined(__linux)
#ifndef __linux__
#define __linux__ 1
#endif
#endif

/* GNU/Linux (__gnu_linux__) */

/* Apple Platforms (iOS, Mac OS X) */

#if (defined(__APPLE__) && defined(__MACH__))

#include <TargetConditionals.h>

#if (TARGET_OS_IPHONE == 1) || (TARGET_IPHONE_SIMULATOR == 1)

/* iOS (__IOS__) */

#ifndef __IOS__
#define __IOS__ 1
#endif

#elif (TARGET_OS_MAC == 1)

/* Mac OS X (__MACOSX__) */

#ifndef __MACOSX__
#define __MACOSX__ 1
#endif

#endif
#endif

/* Android (__ANDROID__) */

/* Cygwin (__CYGWIN__) */

/* FreeBSD (__FreeBSD__) */

/* NetBSD (__NetBSD__) */

/* OpenBSD (__OpenBSD__) */

/* DragonFly (__DragonFly__) */

/* Solaris (__sun) */

#if defined(sun)
#ifndef __sun
#define __sun 1
#endif
#endif

/* IRIX (__sgi) */

#if defined(sgi)
#ifndef __sgi
#define __sgi 1
#endif
#endif

/* AIX (_AIX) */

#if defined(__TOS_AIX__)
#ifndef _AIX
#define _AIX 1
#endif
#endif

/* HP-UX (__hpux) */

#if defined(hpux) || defined(_hpux)
#ifndef __hpux
#define __hpux 1
#endif
#endif

/* BeOS (__BEOS__) */

/* QNX (__QNXNTO__) */

/**
 * Endianness:
 * http://sourceforge.net/p/predef/wiki/Endianness/
 */

#if defined(__gnu_linux__)
#include <endian.h>
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__) || defined(__APPLE__)
#include <sys/param.h>
#endif

/* Big-Endian */

#ifdef __BYTE_ORDER

#if (__BYTE_ORDER == __BIG_ENDIAN)
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__ 1
#endif
#endif

#else

#if defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || defined(_MIPSEB) || \
    defined(__MIPSEB) || defined(__MIPSEB__)
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__ 1
#endif
#endif

#endif /* __BYTE_ORDER */

/* Little-Endian */

#ifdef __BYTE_ORDER

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__ 1
#endif
#endif

#else

#if defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) || defined(_MIPSEL) || \
    defined(__MIPSEL) || defined(__MIPSEL__) || defined(__e2k__)
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__ 1
#endif
#endif

#endif /* __BYTE_ORDER */

WINPR_PRAGMA_DIAG_POP

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 202311L)
#define WINPR_DEPRECATED(obj) [[deprecated]] obj
#define WINPR_DEPRECATED_VAR(text, obj) [[deprecated(text)]] obj
#define WINPR_NORETURN(obj) [[noreturn]] obj
#elif defined(WIN32) && !defined(__CYGWIN__)
#define WINPR_DEPRECATED(obj) __declspec(deprecated) obj
#define WINPR_DEPRECATED_VAR(text, obj) __declspec(deprecated(text)) obj
#define WINPR_NORETURN(obj) __declspec(noreturn) obj
#elif defined(__GNUC__)
#define WINPR_DEPRECATED(obj) obj __attribute__((deprecated))
#define WINPR_DEPRECATED_VAR(text, obj) obj __attribute__((deprecated(text)))
#define WINPR_NORETURN(obj) __attribute__((__noreturn__)) obj
#else
#define WINPR_DEPRECATED(obj) obj
#define WINPR_DEPRECATED_VAR(text, obj) obj
#define WINPR_NORETURN(obj) obj
#endif

#ifdef _WIN32
#define INLINE __inline
#else
#define INLINE inline
#endif

#ifdef WINPR_DLL
#if defined _WIN32 || defined __CYGWIN__
#ifdef WINPR_EXPORTS
#ifdef __GNUC__
#define WINPR_API __attribute__((dllexport))
#else
#define WINPR_API __declspec(dllexport)
#endif
#else
#ifdef __GNUC__
#define WINPR_API __attribute__((dllimport))
#else
#define WINPR_API __declspec(dllimport)
#endif
#endif
#else
#if defined(__GNUC__) && (__GNUC__ >= 4)
#define WINPR_API __attribute__((visibility("default")))
#else
#define WINPR_API
#endif
#endif
#else /* WINPR_DLL */
#define WINPR_API
#endif

#if defined(__clang__) || defined(__GNUC__) && (__GNUC__ <= 10)
#define WINPR_ATTR_MALLOC(deallocator, ptrindex) \
	__attribute__((malloc, warn_unused_result)) /** @since version 3.3.0 */
#elif defined(__GNUC__)
#define WINPR_ATTR_MALLOC(deallocator, ptrindex) \
	__attribute__((malloc(deallocator, ptrindex), warn_unused_result)) /** @since version 3.3.0 */
#else
#define WINPR_ATTR_MALLOC(deallocator, ptrindex) __declspec(restrict) /** @since version 3.3.0 */
#endif

#if defined(__GNUC__) || defined(__clang__)
#define WINPR_ATTR_FORMAT_ARG(pos, args) __attribute__((__format__(__printf__, pos, args)))
#define WINPR_FORMAT_ARG /**/
#else
#define WINPR_ATTR_FORMAT_ARG(pos, args)
#define WINPR_FORMAT_ARG _Printf_format_string_
#endif

#if defined(EXPORT_ALL_SYMBOLS)
#define WINPR_LOCAL WINPR_API
#else
#if defined _WIN32 || defined __CYGWIN__
#define WINPR_LOCAL
#else
#if defined(__GNUC__) && (__GNUC__ >= 4)
#define WINPR_LOCAL __attribute__((visibility("hidden")))
#else
#define WINPR_LOCAL
#endif
#endif
#endif

// WARNING: *do not* use thread-local storage for new code because it is not portable
// It is only used for VirtualChannelInit, and all FreeRDP channels use VirtualChannelInitEx
// The old virtual channel API is only realistically used on Windows where TLS is available
#if defined _WIN32 || defined __CYGWIN__
#ifdef __GNUC__
#define WINPR_TLS __thread
#else
#define WINPR_TLS __declspec(thread)
#endif
#elif !defined(__IOS__)
#define WINPR_TLS __thread
#else
// thread-local storage is not supported on iOS
// don't warn because it isn't actually used on iOS
#define WINPR_TLS
#endif

#if defined(__GNUC__) || defined(__clang__)
#define WINPR_ALIGN64 __attribute__((aligned(8))) /** @since version 3.4.0 */
#else
#ifdef _WIN32
#define WINPR_ALIGN64 __declspec(align(8)) /** @since version 3.4.0 */
#else
#define WINPR_ALIGN64 /** @since version 3.4.0 */
#endif
#endif

#if defined(__cplusplus) && (__cplusplus >= 201703L)
#define WINPR_ATTR_UNUSED [[maybe_unused]] /** @since version 3.12.0 */
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 202000L)
#define WINPR_ATTR_UNUSED [[maybe_unused]] /** @since version 3.12.0 */
#elif defined(__GNUC__) || defined(__clang__)
#define WINPR_ATTR_UNUSED __attribute__((unused)) /** @since version 3.12.0 */
#else
#define WINPR_ATTR_UNUSED /** @since version 3.12.0 */
#endif

#define WINPR_UNUSED(x) (void)(x)

#endif /* WINPR_PLATFORM_H */
