//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift open source project
//
// Copyright (c) 2025 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
// See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

import Foundation
import SWBLibc

#if canImport(Darwin)
import Darwin
import MachO
#if canImport(MachO.dyld.utils)
import MachO.dyld.utils
#endif
#endif

public struct Architecture: Sendable {
    private let cputype: cpu_type_t

    private init(cputype: cpu_type_t = CPU_TYPE_ANY) {
        self.cputype = cputype
    }

    /// Returns the native architecture of the host machine, not including subtypes like arm64e and x86_64h.
    public static let host: Architecture = {
        #if canImport(Darwin) && canImport(MachO.dyld.utils)
        if let value = macho_arch_name_for_mach_header(nil) {
            var cputype: cpu_type_t = 0
            var cpusubtype: cpu_subtype_t = 0
            if macho_cpu_type_for_arch_name(value, &cputype, &cpusubtype) {
                return Self(cputype: cputype)
            }
        }
        #endif
        return Self()
    }()

    /// Returns the 32-bit counterpart of the architecture, which may be the same value.
    public var as32bit: Architecture {
        #if canImport(Darwin)
        return Self(cputype: cputype & ~CPU_ARCH_ABI64)
        #else
        return Self()
        #endif
    }

    /// Returns the 64-bit counterpart of the architecture, which may be the same value.
    public var as64bit: Architecture {
        #if canImport(Darwin)
        return Self(cputype: cputype | CPU_ARCH_ABI64)
        #else
        return Self()
        #endif
    }

    /// Returns the string representation of the architecture, or `nil` if it cannot be determined.
    public var stringValue: String? {
        #if canImport(Darwin)
        // This only needs to consider the known 4 values as it's only for computing the host architecture build settings.
        switch cputype {
        case CPU_TYPE_ARM:
            return "arm"
        case CPU_TYPE_ARM64:
            return "arm64"
        case CPU_TYPE_I386:
            return "i386"
        case CPU_TYPE_X86_64:
            return "x86_64"
        default:
            break
        }
        #endif
        return nil
    }

    public static var hostStringValue: String? {
        return host.stringValue ?? { () -> String? in
            #if os(Windows)
            var sysInfo = SYSTEM_INFO()
            GetSystemInfo(&sysInfo)
            switch Int32(sysInfo.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64:
                return "x86_64"
            case PROCESSOR_ARCHITECTURE_ARM64:
                return "aarch64"
            default:
                return nil
            }
            #else
            var buf = utsname()
            if uname(&buf) == 0 {
                return withUnsafeBytes(of: &buf.machine) { buf in
                    let data = Data(buf)
                    let value = String(decoding: data[0...(data.lastIndex(where: { $0 != 0 }) ?? 0)], as: UTF8.self)
                    #if os(FreeBSD) || os(OpenBSD)
                    switch value {
                    case "amd64":
                        return "x86_64"
                    case "arm64":
                        return "aarch64"
                    default:
                        break
                    }
                    #endif
                    return value
                }
            }
            return nil
            #endif
        }()
    }

    static func stringValue(cputype: cpu_type_t, cpusubtype: cpu_subtype_t) -> String? {
        #if canImport(Darwin) && canImport(MachO.dyld.utils)
        if let value = macho_arch_name_for_cpu_type(cputype, cpusubtype).map(String.init(cString:)) {
            return value
        }
        // rdar://166572383: This is a hack to handle the fact that not all environments recognize this arch subtype yet. Once they do, or if we ever move to linking against a static library for dyld, we should remove this.
        if cputype == CPU_TYPE_ARM64, (UInt32(bitPattern: cpusubtype) & ~CPU_SUBTYPE_MASK) == 12 {
            return "arm64e.x1"
        }
        return nil
        #else
        // The names macho_arch_name_for_cpu_type gives on Darwin, which ignores the subtype's capability bits.
        switch (UInt32(bitPattern: cputype), UInt32(bitPattern: cpusubtype) & 0x00ff_ffff) {
        case (0x0000_0007, 3): return "i386"
        case (0x0100_0007, 3): return "x86_64"
        case (0x0100_0007, 8): return "x86_64h"
        case (0x0000_000c, 6): return "armv6"
        case (0x0000_000c, 9): return "armv7"
        case (0x0000_000c, 11): return "armv7s"
        case (0x0000_000c, 12): return "armv7k"
        case (0x0000_000c, 14): return "armv6m"
        case (0x0000_000c, 15): return "armv7m"
        case (0x0000_000c, 16): return "armv7em"
        case (0x0100_000c, 0), (0x0100_000c, 1): return "arm64"
        case (0x0100_000c, 2): return "arm64e"
        case (0x0100_000c, 12): return "arm64e.x1"
        case (0x0200_000c, 0), (0x0200_000c, 1): return "arm64_32"
        case (0x0000_0012, 0): return "ppc"
        default: return nil
        }
        #endif
    }
}
