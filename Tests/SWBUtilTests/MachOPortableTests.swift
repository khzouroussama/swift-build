//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
// See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

import Testing
@_spi(Testing) import SWBUtil

/// Mach-O files read on every platform, from bytes written here rather than by a toolchain.
@Suite fileprivate struct MachOPortableTests {
    /// A thin arm64 dylib with a `__TEXT,__swift5_entry` section, an install name, an rpath and a
    /// build version, laid out as <mach-o/loader.h> describes.
    static func dylib() -> [UInt8] {
        var bytes: [UInt8] = []
        func u32(_ value: UInt32) { withUnsafeBytes(of: value.littleEndian) { bytes += $0 } }
        func u64(_ value: UInt64) { withUnsafeBytes(of: value.littleEndian) { bytes += $0 } }
        func name(_ string: String, size: Int = 16) { bytes += Array(string.utf8) + Array(repeating: 0, count: size - string.utf8.count) }
        let installName = "@rpath/libT.dylib"
        let rpath = "@loader_path/Frameworks"
        let commands: UInt32 = 152 + 48 + 40 + 24
        u32(0xfeedfacf); u32(0x0100_000c); u32(0); u32(0x6); u32(4); u32(commands); u32(0); u32(0)
        // LC_SEGMENT_64 __TEXT with one section, __swift5_entry.
        u32(0x19); u32(152); name("__TEXT"); u64(0); u64(0x4000); u64(0); u64(0x4000); u32(5); u32(5); u32(1); u32(0)
        name("__swift5_entry"); name("__TEXT"); u64(0x1000); u64(4); u32(0x1000); u32(2); u32(0); u32(0); u32(0); u32(0); u32(0); u32(0)
        // LC_ID_DYLIB, its name after the command's 24 bytes.
        u32(0xd); u32(48); u32(24); u32(0); u32(0x0001_0000); u32(0x0001_0000); name(installName, size: 24)
        // LC_RPATH, its path after the command's 12 bytes.
        u32(0x8000_001c); u32(40); u32(12); name(rpath, size: 28)
        // LC_BUILD_VERSION: iOS 15.0, SDK 27.0, no tools.
        u32(0x32); u32(24); u32(2); u32(0x000f_0000); u32(0x001b_0000); u32(0)
        return bytes + Array(repeating: 0, count: 0x1004 - bytes.count)
    }

    @Test
    func thinDylib() throws {
        let machO = try MachO(data: ByteString(Self.dylib()))
        let slices = try machO.slices()
        #expect(slices.count == 1)
        let slice = try #require(slices.first)
        #expect(try slice.containsSwift5EntrySection)
        #expect(try slice.installName() == "@rpath/libT.dylib")
        #expect(try slice.rpaths() == ["@loader_path/Frameworks"])
        #expect(try slice.buildVersions().map(\.platform) == [.iOS])
        #expect(try slice.segments().count == 1)
    }

    /// A universal static library of two slices, each an archive with a symbol table and one
    /// object, its name in the extended format (`#1/<length>`), as libtool writes them.
    static func universalStaticLibrary() -> [UInt8] {
        func header(_ name: String, size: Int) -> [UInt8] {
            func field(_ value: String, _ width: Int) -> [UInt8] { Array(value.utf8) + Array(repeating: 0x20, count: width - value.utf8.count) }
            return field(name, 16) + field("0", 12) + field("0", 6) + field("0", 6) + field("100644", 8) + field(String(size), 10) + Array("`\n".utf8)
        }
        var object: [UInt8] = []
        func u32(_ value: UInt32) { withUnsafeBytes(of: value.littleEndian) { object += $0 } }
        u32(0xfeedfacf); u32(0x0100_000c); u32(0); u32(0x1); u32(0); u32(0); u32(0); u32(0)
        let name = Array("Basics.o".utf8) + [0, 0, 0, 0]
        let symbols = Array("__.SYMDEF\0\0\0".utf8) + Array(repeating: 0, count: 8)
        let archive = Array("!<arch>\n".utf8) + header("#1/12", size: 12 + 8) + Array(symbols.prefix(20))
            + header("#1/\(name.count)", size: name.count + object.count) + name + object
        var bytes: [UInt8] = []
        func be(_ value: UInt32) { withUnsafeBytes(of: value.bigEndian) { bytes += $0 } }
        be(0xcafebabe); be(2)
        let first = 4096
        let second = first + ((archive.count + 4095) / 4096) * 4096
        be(0x0100_000c); be(0); be(UInt32(first)); be(UInt32(archive.count)); be(12)
        be(12); be(9); be(UInt32(second)); be(UInt32(archive.count)); be(12)
        bytes += Array(repeating: 0, count: first - bytes.count) + archive
        bytes += Array(repeating: 0, count: second - bytes.count) + archive
        return bytes
    }

    @Test
    func universalStaticLibraryOfArchives() throws {
        let (slices, linkage) = try MachO(data: ByteString(Self.universalStaticLibrary())).slicesIncludingLinkage()
        #expect(linkage == .static)
        #expect(slices.count == 2)
    }
}
