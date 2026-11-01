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
import Testing
@testable import SWBUtil
import SWBTestSupport

@Suite fileprivate struct ArchitectureTests {
    @Test func hostArchitecture() async throws {
        #if canImport(Darwin)
        #if arch(arm64)
        #expect(Architecture.host.stringValue == "arm64")
        #expect(Architecture.host.as32bit.stringValue == "arm")
        #expect(Architecture.host.as64bit.stringValue == "arm64")
        #endif

        #if arch(x86_64)
        #expect(Architecture.host.stringValue == "x86_64")
        #expect(Architecture.host.as32bit.stringValue == "i386")
        #expect(Architecture.host.as64bit.stringValue == "x86_64")
        #endif
        #else
        #expect(Architecture.host.stringValue == nil)

        #if arch(arm64)
        #expect(Architecture.hostStringValue == "aarch64")
        #endif

        #if arch(x86_64)
        #expect(Architecture.hostStringValue == "x86_64")
        #endif
        #endif
    }

    @Test func namesOfCPUTypesAndSubtypes() {
        let names: [(UInt32, UInt32, String?)] = [
            (0x0000_0007, 3, "i386"), (0x0100_0007, 3, "x86_64"), (0x0100_0007, 8, "x86_64h"), (0x0000_0007, 8, nil),
            (0x0000_000c, 9, "armv7"), (0x0000_000c, 11, "armv7s"), (0x0000_000c, 12, "armv7k"), (0x0000_000c, 0, nil),
            (0x0100_000c, 0, "arm64"), (0x0100_000c, 1, "arm64"), (0x0100_000c, 2, "arm64e"), (0x0100_000c, 0x8000_0002, "arm64e"),
            (0x0100_000c, 0x8100_0002, "arm64e"), (0x0100_000c, 12, "arm64e.x1"), (0x0200_000c, 1, "arm64_32"), (0x0100_0012, 0, nil),
        ]
        for (cputype, cpusubtype, name) in names {
            #expect(Architecture.stringValue(cputype: cpu_type_t(bitPattern: cputype), cpusubtype: cpu_subtype_t(bitPattern: cpusubtype)) == name)
        }
    }
}
