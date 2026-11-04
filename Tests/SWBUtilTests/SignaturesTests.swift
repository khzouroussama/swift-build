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
import SWBUtil
import SWBTestSupport

@Suite(.requireHostOS(.macOS), .requireSDKs(.macOS))
fileprivate struct SignaturesTests {
    let fs = localFS

    @Test
    func basics() async throws {
        try await withTemporaryDirectory { tmpDir in
            let rootPath: Path = tmpDir.path
            let bundlePath = rootPath.join("test.bundle")
            try fs.createDirectory(bundlePath, recursive: true)
            try await fs.writePlist(bundlePath.join("Info.plist"), .plDict([:]))
            try fs.write(bundlePath.join("test"), contents: "#!/bin/bash", atomically: true)

            let codesignTool = URL(fileURLWithPath: "/usr/bin/codesign")

            // Set-up the ad-hoc signed bundle for testing.
            let codesignSigningResult = try await Process.run(url: codesignTool, arguments: ["-s", "-", "-i", "test-ident", bundlePath.str])
            #expect(codesignSigningResult.isSuccess)

            let info = try await CodeSignatureInfo.load(from: bundlePath.str, additionalInfo: nil)
            #expect(info.identifier == "test-ident")
        }
    }

    @Test
    func errorWithModifiedContent() async throws {
        try await withTemporaryDirectory { tmpDir in
            let rootPath: Path = tmpDir.path
            let bundlePath = rootPath.join("test.bundle")
            try fs.createDirectory(bundlePath, recursive: true)
            try await fs.writePlist(bundlePath.join("Info.plist"), .plDict([:]))
            try fs.write(bundlePath.join("test"), contents: "#!/bin/bash", atomically: true)

            let codesignTool = URL(fileURLWithPath: "/usr/bin/codesign")

            // Set-up the ad-hoc signed bundle for testing.
            let codesignSigningResult = try await Process.run(url: codesignTool, arguments: ["-s", "-", bundlePath.str])
            #expect(codesignSigningResult.isSuccess)

            // Modify the contents of the test bundle to ensure that `codesign -v` will fail.
            try fs.copy(Path("\(bundlePath.str)/Info.plist"), to: Path("\(bundlePath.str)/Info-Copy.plist"))

            do {
                _ = try await CodeSignatureInfo.load(from: bundlePath, additionalInfo: nil)
                Issue.record("Expected an error to be thrown, but it was not.")
            } catch let CodeSignatureInfo.Error.codesignVerificationFailed(description, output) {
                #expect(description == "A sealed resource is missing or invalid")
                #expect(try output.split(separator: "\n").filter { line in
                    try #/--(prepared|validated):/.+/Contents/Frameworks/libclang_rt\.(asan|tsan|ubsan)_osx_dynamic\.dylib/#.wholeMatch(in: line) == nil
                } == [
                    "\(bundlePath.str): a sealed resource is missing or invalid",
                    "file added: \(bundlePath.str)/Info-Copy.plist"
                ])
            } catch {
                Issue.record(error)
            }
        }
    }

    @Test
    func noErrorWithModifiedContentNoSignature() async throws {
        try await withTemporaryDirectory { (tmpDir: NamedTemporaryDirectory) in
            let rootPath: Path = tmpDir.path
            let bundlePath = rootPath.join("test.bundle")
            try fs.createDirectory(bundlePath, recursive: true)
            try await fs.writePlist(bundlePath.join("Info.plist"), .plDict([:]))
            try fs.write(bundlePath.join("test"), contents: "#!/bin/bash", atomically: true)

            // Modify the contents of the test bundle to ensure that `codesign -v` will fail.
            try fs.copy(Path("\(bundlePath.str)/Info.plist"), to: Path("\(bundlePath.str)/Info-Copy.plist"))

            await #expect(throws: Never.self) {
                try await CodeSignatureInfo.load(from: bundlePath, additionalInfo: nil)
            }
        }
    }
}

#if !os(macOS)
/// Signatures written by hand with the shapes `codesign` gives them; `signature_record_experiments.py` in nomac has compared what is read from real ones with the records of Xcode 27.0.
@Suite
fileprivate struct SignatureBytesTests {
    let fs = localFS

    func withBundle(_ files: [String: [UInt8]], _ body: (String) async throws -> Void) async throws {
        try await withTemporaryDirectory { tmpDir in
            let bundlePath = tmpDir.path.join("Vendor.xcframework")
            try fs.createDirectory(bundlePath.join("_CodeSignature"), recursive: true)
            for (name, bytes) in files {
                try fs.write(bundlePath.join("_CodeSignature").join(name), contents: ByteString(bytes))
            }
            try await body(bundlePath.str)
        }
    }

    func big32(_ value: Int) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> (24 - 8 * $0)) }
    }

    func codeDirectory(hashType: UInt8, team: String? = nil) -> [UInt8] {
        let identifier = Array("Vendor".utf8) + [0]
        let headerSize = team == nil ? 48 : 52
        let length = headerSize + identifier.count + (team.map { $0.utf8.count + 1 } ?? 0)
        var blob = big32(0xfade_0c02) + big32(length) + big32(team == nil ? 0x20100 : 0x20200) + big32(0x2) + big32(0) + big32(headerSize)
        blob += big32(0) + big32(0) + big32(0) + [hashType == 1 ? 20 : 32, hashType, 0, 0] + big32(0) + big32(0)
        if let team {
            blob += big32(headerSize + identifier.count)
            return blob + identifier + Array(team.utf8) + [0]
        }
        return blob + identifier
    }

    func der(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        let length: [UInt8] = content.count < 0x80 ? [UInt8(content.count)] : [0x82, UInt8(content.count >> 8), UInt8(content.count & 0xff)]
        return [tag] + length + content
    }

    func name(_ value: String) -> [UInt8] {
        der(0x30, der(0x0c, Array(value.utf8)))
    }

    func certificate(serial: UInt8, issuer: String, subject: String) -> [UInt8] {
        let version = der(0xa0, der(0x02, [2]))
        let algorithm = der(0x30, [])
        return der(0x30, der(0x30, version + der(0x02, [serial]) + algorithm + name(issuer) + der(0x30, []) + name(subject)) + algorithm + der(0x03, [0]))
    }

    /// A CMS `ContentInfo`, its outer elements with indefinite lengths as `codesign` writes them.
    func signature(certificates: [[UInt8]], signerIssuer: String, signerSerial: UInt8) -> [UInt8] {
        let signerInfo = der(0x30, der(0x02, [1]) + der(0x30, name(signerIssuer) + der(0x02, [signerSerial])))
        let signedData = der(0x02, [1]) + der(0x31, []) + [0x30, 0x80, 0x06, 0x01, 0x01, 0, 0] + der(0xa0, certificates.flatMap { $0 }) + der(0x31, signerInfo)
        return [0x30, 0x80, 0x06, 0x01, 0x01, 0xa0, 0x80, 0x30, 0x80] + signedData + [0, 0, 0, 0, 0, 0]
    }

    var leaf: [UInt8] { certificate(serial: 3, issuer: "Intermediate", subject: "Signer") }
    var intermediate: [UInt8] { certificate(serial: 2, issuer: "Root", subject: "Intermediate") }
    var root: [UInt8] { certificate(serial: 1, issuer: "Root", subject: "Root") }

    @Test
    func unsigned() async throws {
        try await withBundle(["CodeResources": []]) { path in
            let info = try await CodeSignatureInfo.load(from: path, additionalInfo: ["platform": "ios"])
            #expect(!info.isSigned)
            #expect(info.identifier == nil)
            #expect(info.source == nil)
            #expect(info.cdHashes == nil)
            #expect(info.certificates == nil)
            #expect(info.signatureType == nil)
            #expect(info.additionalInfo == ["platform": "ios"])
        }
    }

    @Test
    func adHoc() async throws {
        for files in [["CodeDirectory": codeDirectory(hashType: 2), "CodeSignature": []], ["CodeDirectory": codeDirectory(hashType: 2)]] {
            try await withBundle(files) { path in
                let info = try await CodeSignatureInfo.load(from: path, additionalInfo: nil)
                #expect(info.isSigned)
                #expect(info.identifier == "Vendor")
                #expect(info.source == "embedded")
                #expect(info.cdHashes?.map { $0.map { String(format: "%02x", $0) }.joined() } == ["f5a4589ff6e5fe6ce2f25dc5d434bfbf606f25b6"])
                #expect(info.certificates == nil)
                #expect(info.signatureType == nil)
                #expect(info.signatureIdentifier == nil)
                #expect(info.timestamp == nil)
                #expect(!info.isSecureTimestamp)
            }
        }
    }

    @Test
    func alternateDigests() async throws {
        try await withBundle(["CodeDirectory": codeDirectory(hashType: 1), "CodeRequirements-1": codeDirectory(hashType: 2)]) { path in
            let info = try await CodeSignatureInfo.load(from: path, additionalInfo: nil)
            #expect(info.cdHashes?.map { $0.map { String(format: "%02x", $0) }.joined() } == ["d2484ed7d07b90873351e605a91a5f1f6746185a", "f5a4589ff6e5fe6ce2f25dc5d434bfbf606f25b6"])
        }
    }

    @Test
    func certificatesFromTheSignerToTheRoot() async throws {
        let bytes = signature(certificates: [root, intermediate, leaf], signerIssuer: "Intermediate", signerSerial: 3)
        try await withBundle(["CodeDirectory": codeDirectory(hashType: 2), "CodeSignature": bytes]) { path in
            let info = try await CodeSignatureInfo.load(from: path, additionalInfo: nil)
            #expect(info.certificates == [Data(leaf), Data(intermediate), Data(root)])
            #expect(info.signatureType == .selfSigned)
            #expect(info.signatureIdentifier == Data(leaf).sha256HexString)
        }
    }

    @Test
    func teamIdentifier() async throws {
        let bytes = signature(certificates: [leaf, root, intermediate], signerIssuer: "Intermediate", signerSerial: 3)
        try await withBundle(["CodeDirectory": codeDirectory(hashType: 2, team: "ABCDE12345"), "CodeSignature": bytes]) { path in
            let info = try await CodeSignatureInfo.load(from: path, additionalInfo: nil)
            #expect(info.signatureType == .appleDeveloperProgram)
            #expect(info.signatureIdentifier == "ABCDE12345")
            #expect(info.certificates?.count == 3)
        }
    }

    @Test
    func refusesWhatItCannotRead() async throws {
        let withoutRoot = signature(certificates: [leaf, intermediate], signerIssuer: "Intermediate", signerSerial: 3)
        let otherSigner = signature(certificates: [leaf, intermediate, root], signerIssuer: "Intermediate", signerSerial: 9)
        let cases: [[String: [UInt8]]] = [
            ["CodeDirectory": Array(codeDirectory(hashType: 2).prefix(20))],
            ["CodeDirectory": codeDirectory(hashType: 3)],
            ["CodeDirectory": codeDirectory(hashType: 4)],
            ["CodeDirectory": codeDirectory(hashType: 2), "CodeRequirements-1": [0]],
            ["CodeDirectory": codeDirectory(hashType: 2), "CodeSignature": [1, 2, 3]],
            ["CodeDirectory": codeDirectory(hashType: 2), "CodeSignature": withoutRoot],
            ["CodeDirectory": codeDirectory(hashType: 2), "CodeSignature": otherSigner],
        ]
        for files in cases {
            try await withBundle(files) { path in
                await #expect(throws: CodeSignatureInfo.Error.self) {
                    try await CodeSignatureInfo.load(from: path, additionalInfo: nil)
                }
                await #expect(throws: CodeSignatureInfo.Error.self) {
                    try await CodeSignatureInfo.invokeCodesignVerification(for: path, treatUnsignedAsError: false)
                }
            }
        }
    }

    @Test
    func refusalsGiveTheirReason() async throws {
        try await withBundle(["CodeDirectory": Array(codeDirectory(hashType: 2).prefix(20))]) { path in
            do {
                _ = try await CodeSignatureInfo.load(from: path, additionalInfo: nil)
                Issue.record("Expected an error to be thrown, but it was not.")
            } catch {
                #expect(error.localizedDescription == "Codesign verification failed: \(path): unsupported type or version of signature")
            }
        }
    }

    @Test
    func unsignedAsAnError() async throws {
        try await withBundle([:]) { path in
            await #expect(throws: CodeSignatureInfo.Error.self) {
                try await CodeSignatureInfo.invokeCodesignVerification(for: path, treatUnsignedAsError: true)
            }
            try await CodeSignatureInfo.invokeCodesignVerification(for: path, treatUnsignedAsError: false)
        }
    }
}
#endif
