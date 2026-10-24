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

import Foundation

/// The binary property lists `swb_stableData` writes on Darwin, written without Foundation, for
/// platforms whose Foundation does not honor `SWBStablePropertyListDictionary`'s key order and
/// shares strings by identity: dictionary keys sorted, equal strings and integers written once,
/// objects depth first, as Core Foundation lays them out.
enum BinaryPropertyListWriter {
    static func data(_ item: PropertyListItem) -> [UInt8] {
        var writer = Writer()
        writer.flatten(item)
        return writer.serialized()
    }

    private enum Object {
        case boolean(Bool)
        case integer(Int)
        case real(Double)
        case date(Double)
        case data([UInt8])
        case string(String)
        case array([Int])
        case dictionary(keys: [Int], values: [Int])
    }

    private struct Writer {
        var objects: [Object] = []
        var strings: [[UInt16]: Int] = [:]
        var integers: [Int: Int] = [:]
        var booleans: [Bool: Int] = [:]

        @discardableResult
        mutating func flatten(_ item: PropertyListItem) -> Int {
            switch item {
            case .plString(let string):
                let units = Array(string.utf16)
                if let index = strings[units] { return index }
                strings[units] = objects.count
                return append(.string(string))
            case .plInt(let integer):
                if let index = integers[integer] { return index }
                integers[integer] = objects.count
                return append(.integer(integer))
            case .plBool(let boolean):
                let index = append(.boolean(boolean))
                if let first = booleans[boolean] { return first }
                booleans[boolean] = index
                return index
            case .plDouble(let real):
                return append(.real(real))
            case .plDate(let date):
                return append(.date(date.timeIntervalSinceReferenceDate))
            case .plData(let bytes):
                return append(.data(bytes))
            case .plArray(let elements):
                let index = append(.array([]))
                let references = elements.map { flatten($0) }
                objects[index] = .array(references)
                return index
            case .plDict(let entries):
                let index = append(.dictionary(keys: [], values: []))
                let keys = entries.keys.sorted()
                let keyReferences = keys.map { flatten(.plString($0)) }
                let valueReferences = keys.map { flatten(entries[$0]!) }
                objects[index] = .dictionary(keys: keyReferences, values: valueReferences)
                return index
            case .plOpaque:
                preconditionFailure("opaque property list items have no binary encoding")
            }
        }

        private mutating func append(_ object: Object) -> Int {
            objects.append(object)
            return objects.count - 1
        }

        func serialized() -> [UInt8] {
            let referenceSize = byteCount(objects.count)
            var bytes: [UInt8] = Array("bplist00".utf8)
            var offsets: [Int] = []
            for object in objects {
                offsets.append(bytes.count)
                encode(object, referenceSize: referenceSize, into: &bytes)
            }
            let tableOffset = bytes.count
            let offsetSize = byteCount(tableOffset)
            for offset in offsets {
                bytes += bigEndian(offset, size: offsetSize)
            }
            bytes += [0, 0, 0, 0, 0, 0, UInt8(offsetSize), UInt8(referenceSize)]
            bytes += bigEndian(objects.count, size: 8) + bigEndian(0, size: 8) + bigEndian(tableOffset, size: 8)
            return bytes
        }

        private func encode(_ object: Object, referenceSize: Int, into bytes: inout [UInt8]) {
            switch object {
            case .boolean(let boolean):
                bytes.append(boolean ? 0x09 : 0x08)
            case .integer(let integer):
                bytes += integerObject(integer)
            case .real(let real):
                bytes.append(0x23)
                bytes += bigEndian(Int(bitPattern: UInt(real.bitPattern)), size: 8)
            case .date(let date):
                bytes.append(0x33)
                bytes += bigEndian(Int(bitPattern: UInt(date.bitPattern)), size: 8)
            case .data(let data):
                bytes += marker(0x40, count: data.count) + data
            case .string(let string):
                if string.unicodeScalars.allSatisfy(\.isASCII) {
                    bytes += marker(0x50, count: string.utf8.count) + Array(string.utf8)
                } else {
                    let units = Array(string.utf16)
                    bytes += marker(0x60, count: units.count)
                    for unit in units {
                        bytes += [UInt8(unit >> 8), UInt8(unit & 0xFF)]
                    }
                }
            case .array(let references):
                bytes += marker(0xA0, count: references.count)
                for reference in references {
                    bytes += bigEndian(reference, size: referenceSize)
                }
            case .dictionary(let keys, let values):
                bytes += marker(0xD0, count: keys.count)
                for reference in keys + values {
                    bytes += bigEndian(reference, size: referenceSize)
                }
            }
        }

        private func marker(_ type: UInt8, count: Int) -> [UInt8] {
            count < 15 ? [type | UInt8(count)] : [type | 0x0F] + integerObject(count)
        }

        private func integerObject(_ integer: Int) -> [UInt8] {
            let size = integer < 0 ? 8 : byteCount(integer)
            let exponent: UInt8 = size == 1 ? 0 : size == 2 ? 1 : size == 4 ? 2 : 3
            return [0x10 | exponent] + bigEndian(integer, size: size)
        }

        private func byteCount(_ value: Int) -> Int {
            value <= 0xFF ? 1 : value <= 0xFFFF ? 2 : value <= 0xFFFF_FFFF ? 4 : 8
        }

        private func bigEndian(_ value: Int, size: Int) -> [UInt8] {
            (0..<size).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
        }
    }
}
