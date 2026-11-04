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

public import Foundation
#if os(macOS)
private import Security
#endif

public struct CodeSignatureInfo: Codable, Sendable {
    public enum Error: Swift.Error {
        case notSupported
        case codesignVerificationFailed(description: String, output: String)
    }

    enum CodingKeys: String, CodingKey {
        case isSigned = "signed"
        case identifier = "bundleIndentifier" // NOTE: bundle identifier is mis-spelled
        case mainExecutable = "mainExecutable"
        case source = "source"
        case runtimeVersion = "runtimeVersion"
        case cdHashes = "cdhashes"
        case timestamp = "timestamp"
        case isSecureTimestamp = "isSecureTimestamp"
        case certificates = "certificates"
        case additionalInfo = "metadata"
        case signatureType = "signatureType"
        case signatureIdentifier = "signatureIdentifier"
    }

    // Attributes derived from SecCodeInfo* APIs.
    public let isSigned: Bool
    public let identifier: String?
    public let mainExecutable: String?
    public let source: String?
    public let runtimeVersion: String?
    public let cdHashes: [Data]?
    public let timestamp: String?
    public let isSecureTimestamp: Bool
    public let certificates: [Data]?

    // Custom attributes not returned by SecCodeInfo* APIs.
    public let signatureType: SignatureType?
    public let signatureIdentifier: String?
    public let additionalInfo: [String:String]?

    public enum SignatureType: String, Codable, Sendable {
        case appleDeveloperProgram = "AppleDeveloperProgram"
        case selfSigned = "SelfSigned"
    }

    #if os(macOS)
    init(_ dict: NSDictionary?, additionalInfo: [String:String]?) {
        self.additionalInfo = additionalInfo

        guard let dict else {
            self.isSigned = false
            self.identifier = nil
            self.mainExecutable = nil
            self.source = nil
            self.runtimeVersion = nil
            self.cdHashes = nil
            self.timestamp = nil
            self.isSecureTimestamp = false
            self.certificates = nil

            self.signatureType = nil
            self.signatureIdentifier = nil

            return
        }

        self.identifier = dict[kSecCodeInfoIdentifier] as? String

        // According to `SecCode.h`, this is the recommended way to determine if an item is signed.
        self.isSigned = identifier != nil

        if let certificates = dict[kSecCodeInfoCertificates] as? NSArray {
            self.certificates = certificates.compactMap { SecCertificateCopyData($0 as! SecCertificate) as Data }
        }
        else {
            self.certificates = nil
        }

        // NOTE: Other types of signatures will be supported at a later date: rdar://105992196.
        if let appleDeveloperTeamID = dict[kSecCodeInfoTeamIdentifier] as? String {
            self.signatureType  = SignatureType.appleDeveloperProgram
            self.signatureIdentifier = appleDeveloperTeamID
        }
        else if isSigned {
            // NOTE: "signed" binaries with no code certificates are currently treated as un-signed as there is no
            // real signature data to validate. This is a design choice instead of just relying on the identifier,
            // which could be changed by anyone.
            if let firstCert = self.certificates?.first {
                self.signatureType = SignatureType.selfSigned
                self.signatureIdentifier = firstCert.sha256HexString
            }
            else {
                self.signatureType = nil
                self.signatureIdentifier = nil
            }
        }
        else {
            self.signatureType = nil
            self.signatureIdentifier = nil
        }

        self.mainExecutable = dict[kSecCodeInfoMainExecutable] as? String
        self.source = dict[kSecCodeInfoSource] as? String
        self.runtimeVersion = dict[kSecCodeInfoRuntimeVersion] as? String
        if let hashes = dict[kSecCodeInfoCdHashes] as? NSArray {
            self.cdHashes = hashes.compactMap { $0 as? Data }
        }
        else {
            self.cdHashes = nil
        }

        if let secureTimestamp = dict[kSecCodeInfoTimestamp] as? String {
            self.timestamp = secureTimestamp
            self.isSecureTimestamp = true
        }
        else if let timestamp = dict[kSecCodeInfoTime] as? String {
            self.timestamp = timestamp
            self.isSecureTimestamp = false
        }
        else {
            self.timestamp = nil
            self.isSecureTimestamp = false
        }
    }
    #else
    /// The record of a bundle signed in `_CodeSignature`, as an xcframework is, from the signature's own bytes. A bundle without `CodeDirectory` is not signed. The fields `init(_:additionalInfo:)` reads as strings where `SecCodeCopySigningInformation` gives a URL, a number or a date are never recorded: `mainExecutable`, `runtimeVersion` and `timestamp`.
    init(signedBundle path: String, additionalInfo: [String:String]?) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw Error.notSupported
        }

        self.additionalInfo = additionalInfo
        self.mainExecutable = nil
        self.runtimeVersion = nil
        self.timestamp = nil
        self.isSecureTimestamp = false

        func contents(_ name: String) -> [UInt8]? {
            FileManager.default.contents(atPath: "\(path)/_CodeSignature/\(name)").map { [UInt8]($0) }
        }

        guard let primary = contents("CodeDirectory") else {
            self.isSigned = false
            self.identifier = nil
            self.source = nil
            self.cdHashes = nil
            self.certificates = nil
            self.signatureType = nil
            self.signatureIdentifier = nil
            return
        }

        func unreadable(_ reason: String) -> Error {
            .codesignVerificationFailed(description: "Codesign verification failed", output: "\(path): \(reason)")
        }

        // A signature with several digests has its other code directories in `CodeRequirements-<n>`, `cdhashes` lists them in that order.
        let alternates = (1...5).compactMap { contents("CodeRequirements-\($0)") }
        let directories = ([primary] + alternates).map(CodeDirectoryBlob.init)
        guard let directory = directories[0] else {
            throw unreadable("unsupported type or version of signature")
        }
        var cdHashes = [Data]()
        for candidate in directories {
            guard let cdHash = candidate?.cdHash else {
                throw unreadable("unsupported type or version of signature")
            }
            cdHashes.append(cdHash)
        }

        self.isSigned = true
        self.identifier = directory.identifier
        self.source = "embedded"
        self.cdHashes = cdHashes

        let chain: [Data]?
        do {
            chain = try contents("CodeSignature").map(CMSSignedData.certificateChain).flatMap { $0.isEmpty ? nil : $0 }
        }
        catch let failure as CMSSignedData.Failure {
            throw unreadable(failure.description)
        }
        self.certificates = chain

        if let teamIdentifier = directory.teamIdentifier {
            self.signatureType = SignatureType.appleDeveloperProgram
            self.signatureIdentifier = teamIdentifier
        }
        else if let firstCert = chain?.first {
            self.signatureType = SignatureType.selfSigned
            self.signatureIdentifier = firstCert.sha256HexString
        }
        else {
            self.signatureType = nil
            self.signatureIdentifier = nil
        }
    }
    #endif

    static public func invokeCodesignVerification(for path: String, treatUnsignedAsError: Bool) async throws {
        #if os(macOS)
        let executionResult = try await Process.getOutput(url: URL(filePath: "/usr/bin/codesign"), arguments: ["-vvvv", path])
        let stdoutContent = String(data: executionResult.stdout, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let stderrContent = String(data: executionResult.stderr, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        // codesign puts the `-vvvv` additional content into stdout, whereas the initial message is in stderr.
        let output = "\(stderrContent)\n\(stdoutContent)"

        guard executionResult.exitStatus.isSuccess else {
            if stderrContent.contains("code object is not signed at all") {
                if treatUnsignedAsError {
                    throw CodeSignatureInfo.Error.codesignVerificationFailed(description: "Code object is not signed", output: output)
                }
                else {
                    // this is fine
                    return
                }
            }
            else if stderrContent.contains("a sealed resource is missing or invalid") {
                throw CodeSignatureInfo.Error.codesignVerificationFailed(description: "A sealed resource is missing or invalid", output: output)
            }
            else if stderrContent.contains("CSSMERR_TP_CERT_REVOKED") {
                throw CodeSignatureInfo.Error.codesignVerificationFailed(description: "The signing certificate has been revoked (CSSMERR_TP_CERT_REVOKED)", output: output)
            }
            else {
                throw CodeSignatureInfo.Error.codesignVerificationFailed(description: "Codesign verification failed", output: output)
            }
        }
        #else
        // FIXME:When implementing rdar://107627846, we need to think about out to have this codepath use the ClientExecutionDelegates
        // in order to allow for different platform overrides on execution.
        // Without `codesign` only that the signature can be read is checked, not its sealed resources or its certificates.
        let info = try CodeSignatureInfo(signedBundle: path, additionalInfo: nil)
        if treatUnsignedAsError && !info.isSigned {
            throw CodeSignatureInfo.Error.codesignVerificationFailed(description: "Code object is not signed", output: "\(path): code object is not signed at all")
        }
        #endif
    }

    static public func load(from path: Path, additionalInfo: [String:String]?, skipValidation: Bool = false) async throws -> CodeSignatureInfo {
        return try await Self.load(from: path.str, additionalInfo: additionalInfo, skipValidation: skipValidation)
    }

    static public func load(from path: String, additionalInfo: [String:String]?, skipValidation: Bool = false) async throws -> CodeSignatureInfo {
        #if os(macOS)
        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()

        var info: CFDictionary?
        var code: SecStaticCode?

        let result = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(rawValue: 0), &code)
        if result != 0 {
            throw MacError(result)
        }

        let result2 = SecCodeCopySigningInformation(code!, [SecCSFlags(rawValue: kSecCSSigningInformation)], &info)
        if result2 != 0 {
            throw MacError(result2)
        }

        if !skipValidation {
            try await invokeCodesignVerification(for: path, treatUnsignedAsError: false)
        }

        return CodeSignatureInfo(info as NSDictionary?, additionalInfo: additionalInfo)
        #else
        return try CodeSignatureInfo(signedBundle: path, additionalInfo: additionalInfo)
        #endif
    }
}

#if !os(macOS)
extension CodeSignatureInfo.Error: LocalizedError {
    /// The reason, for `signature-collection failed:`, the only message when this stops a build before ProcessXCFramework runs.
    public var errorDescription: String? {
        switch self {
        case .notSupported:
            return "only the signature of a bundle can be read on this platform"
        case let .codesignVerificationFailed(description, output):
            return "\(description): \(output)"
        }
    }
}

/// A code directory blob (`CS_CodeDirectory` in xnu's public `cs_blobs.h`, fields big endian).
private struct CodeDirectoryBlob {
    let identifier: String
    let teamIdentifier: String?
    /// The first 20 bytes of the digest of the blob, by the digest its `hashType` names.
    let cdHash: Data

    init?(_ bytes: [UInt8]) {
        func field(_ offset: Int) -> Int? {
            guard offset + 4 <= bytes.count else { return nil }
            return bytes[offset..<(offset + 4)].reduce(0) { $0 << 8 | Int($1) }
        }
        func string(at offset: Int, end: Int) -> String? {
            guard offset < end, let terminator = bytes[offset..<end].firstIndex(of: 0) else { return nil }
            return String(decoding: bytes[offset..<terminator], as: UTF8.self)
        }
        guard field(0) == 0xfade_0c02, let length = field(4), let version = field(8), let identifierOffset = field(20),
              bytes.count >= 40, length >= 40, length <= bytes.count, let identifier = string(at: identifierOffset, end: length) else {
            return nil
        }
        self.identifier = identifier

        if version >= 0x20200, let teamOffset = field(48), teamOffset != 0 {
            guard let teamIdentifier = string(at: teamOffset, end: length) else { return nil }
            self.teamIdentifier = teamIdentifier
        }
        else {
            self.teamIdentifier = nil
        }

        let blob = Array(bytes[0..<length])
        switch bytes[37] {
        case 1:
            self.cdHash = Data(Self.sha1(blob).prefix(20))
        case 2:
            let digest = SHA256Context()
            digest.add(bytes: blob)
            let hex = Array(digest.signature.asString)
            self.cdHash = Data(stride(from: 0, to: 40, by: 2).compactMap { UInt8(String(hex[$0...($0 + 1)]), radix: 16) })
        default:
            return nil
        }
    }

    private static func sha1(_ message: [UInt8]) -> [UInt8] {
        var state: [UInt32] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0]
        let padding = (55 - message.count % 64 + 64) % 64
        let bits = UInt64(message.count) * 8
        let padded = message + [0x80] + [UInt8](repeating: 0, count: padding) + (0..<8).map { UInt8(truncatingIfNeeded: bits >> (56 - 8 * UInt64($0))) }
        for block in stride(from: 0, to: padded.count, by: 64) {
            var words = (0..<16).map { word in padded[(block + word * 4)..<(block + word * 4 + 4)].reduce(UInt32(0)) { $0 << 8 | UInt32($1) } }
            for index in 16..<80 {
                let mixed = words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16]
                words.append(mixed << 1 | mixed >> 31)
            }
            var (a, b, c, d, e) = (state[0], state[1], state[2], state[3], state[4])
            for index in 0..<80 {
                let (mix, constant): (UInt32, UInt32)
                switch index {
                case 0..<20: (mix, constant) = ((b & c) | (~b & d), 0x5a82_7999)
                case 20..<40: (mix, constant) = (b ^ c ^ d, 0x6ed9_eba1)
                case 40..<60: (mix, constant) = ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc)
                default: (mix, constant) = (b ^ c ^ d, 0xca62_c1d6)
                }
                let next = (a << 5 | a >> 27) &+ mix &+ e &+ constant &+ words[index]
                (a, b, c, d, e) = (next, a, b << 30 | b >> 2, c, d)
            }
            state = [state[0] &+ a, state[1] &+ b, state[2] &+ c, state[3] &+ d, state[4] &+ e]
        }
        return state.flatMap { word in (0..<4).map { UInt8(truncatingIfNeeded: word >> (24 - 8 * UInt32($0))) } }
    }
}

/// The certificates of a CMS signature (RFC 5652). `codesign` writes the outer elements with indefinite lengths and sorts the certificates by size.
private enum CMSSignedData {
    private struct Element {
        let tag: UInt8
        let content: Range<Int>
        let whole: Range<Int>
    }

    private static func element(_ bytes: [UInt8], at index: Int) -> Element? {
        guard index + 2 <= bytes.count else { return nil }
        let first = Int(bytes[index + 1])
        if first == 0x80 {
            var next = index + 2
            while next + 2 <= bytes.count, bytes[next] != 0 || bytes[next + 1] != 0 {
                guard let child = element(bytes, at: next) else { return nil }
                next = child.whole.upperBound
            }
            guard next + 2 <= bytes.count else { return nil }
            return Element(tag: bytes[index], content: (index + 2)..<next, whole: index..<(next + 2))
        }
        var start = index + 2, length = first
        if first & 0x80 != 0 {
            let count = first & 0x7f
            guard count <= 4, start + count <= bytes.count else { return nil }
            length = bytes[start..<(start + count)].reduce(0) { $0 << 8 | Int($1) }
            start += count
        }
        guard start + length <= bytes.count else { return nil }
        return Element(tag: bytes[index], content: start..<(start + length), whole: index..<(start + length))
    }

    private static func children(_ bytes: [UInt8], _ range: Range<Int>) -> [Element] {
        var result = [Element]()
        var next = range.lowerBound
        while next + 2 <= range.upperBound, bytes[next] != 0 || bytes[next + 1] != 0, let child = element(bytes, at: next) {
            result.append(child)
            next = child.whole.upperBound
        }
        return result
    }

    struct Failure: Swift.Error {
        let description: String
        static let undecodable = Failure(description: "Unknown format in import.")
        static let noChain = Failure(description: "the signature's certificates do not chain from its signer to a self-signed root")
    }

    /// The certificates of the `CodeSignature` file, a bare CMS `ContentInfo`, from the signer's up to its self-signed root, the order `kSecCodeInfoCertificates` has; empty for the empty file of ad hoc code. Without the root the chain `SecCode` builds is not known, so that is refused.
    static func certificateChain(of bytes: [UInt8]) throws -> [Data] {
        if bytes.isEmpty { return [] }

        guard let contentInfo = element(bytes, at: 0),
              let explicit = children(bytes, contentInfo.content).first(where: { $0.tag == 0xa0 }),
              let signedData = children(bytes, explicit.content).first else { throw Failure.undecodable }
        let fields = children(bytes, signedData.content)
        guard let set = fields.first(where: { $0.tag == 0xa0 }), let signerInfos = fields.last(where: { $0.tag == 0x31 }),
              let signerInfo = children(bytes, signerInfos.content).first,
              let issuerAndSerial = children(bytes, signerInfo.content).dropFirst().first, issuerAndSerial.tag == 0x30 else { throw Failure.undecodable }

        struct Certificate {
            let whole: Range<Int>
            let serial: ArraySlice<UInt8>
            let issuer: ArraySlice<UInt8>
            let subject: ArraySlice<UInt8>
        }
        let certificates = children(bytes, set.content).compactMap { certificate -> Certificate? in
            guard let tbs = children(bytes, certificate.content).first else { return nil }
            let items = children(bytes, tbs.content).drop { $0.tag == 0xa0 }.map { bytes[$0.whole] }
            guard items.count >= 5 else { return nil }
            return Certificate(whole: certificate.whole, serial: items[0], issuer: items[2], subject: items[4])
        }

        let signerName = children(bytes, issuerAndSerial.content).map { bytes[$0.whole] }
        guard signerName.count == 2,
              var current = certificates.first(where: { $0.issuer.elementsEqual(signerName[0]) && $0.serial.elementsEqual(signerName[1]) }) else { throw Failure.noChain }
        var chain = [current.whole]
        while !current.issuer.elementsEqual(current.subject) {
            guard let next = certificates.first(where: { $0.subject.elementsEqual(current.issuer) }), !chain.contains(next.whole) else { throw Failure.noChain }
            chain.append(next.whole)
            current = next
        }
        return chain.map { Data(bytes[$0]) }
    }
}
#endif


public extension Data {
    var sha256HexString: String {
        let sha = SHA256Context()
        sha.add(bytes: ByteString(self))
        return sha.signature.asString.uppercased()
    }
}
