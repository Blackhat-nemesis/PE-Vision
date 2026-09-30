/**
 * PEVision — Browser-side PE (Portable Executable) parser.
 * Mirrors functionality of the original Python pe_reader.py tool.
 */
(function (global) {
  'use strict';

  const SUSPICIOUS_APIS = new Set([
    'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread',
    'CreateThread', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress',
    'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'URLDownloadToFileA',
    'URLDownloadToFileW', 'InternetOpenA', 'InternetOpenW', 'InternetConnectA',
    'InternetConnectW', 'HttpOpenRequestA', 'HttpOpenRequestW',
    'RegSetValueExA', 'RegSetValueExW', 'SetWindowsHookEx', 'NtQueryInformationProcess',
  ]);

  const DIRECTORY_NAMES = [
    'EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'SECURITY', 'BASERELOC',
    'DEBUG', 'ARCHITECTURE', 'GLOBALPTR', 'TLS', 'LOAD_CONFIG', 'BOUND_IMPORT',
    'IAT', 'DELAY_IMPORT', 'COM_DESCRIPTOR', 'RESERVED',
  ];

  const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
  const IMAGE_SCN_MEM_READ = 0x40000000;
  const IMAGE_SCN_MEM_WRITE = 0x80000000;

  class PEParser {
    constructor(buffer, fileName) {
      this.buffer = buffer;
      this.fileName = fileName || 'unknown';
      this.view = new DataView(buffer);
      this.u8 = new Uint8Array(buffer);
      this.is64 = false;
    }

    readU16(offset) {
      return this.view.getUint16(offset, true);
    }

    readU32(offset) {
      return this.view.getUint32(offset, true);
    }

    readU64(offset) {
      const lo = this.readU32(offset);
      const hi = this.readU32(offset + 4);
      return hi * 0x100000000 + lo;
    }

    readString(offset) {
      let s = '';
      while (offset < this.u8.length && this.u8[offset] !== 0) {
        s += String.fromCharCode(this.u8[offset++]);
      }
      return s;
    }

    rvaToOffset(rva) {
      for (const sec of this.sections) {
        const vsize = sec.virtualSize || sec.rawSize;
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + vsize) {
          return rva - sec.virtualAddress + sec.rawOffset;
        }
      }
      return rva;
    }

    hex(val, pad = true) {
      const h = val.toString(16);
      return pad ? '0x' + h : h;
    }

    calculateEntropy(data) {
      if (!data || data.length === 0) return 0;
      const counter = new Map();
      for (let i = 0; i < data.length; i++) {
        counter.set(data[i], (counter.get(data[i]) || 0) + 1);
      }
      let entropy = 0;
      const len = data.length;
      for (const count of counter.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }
      return Math.round(entropy * 100) / 100;
    }

    async calculateHashes() {
      const md5 = MD5.hash(this.buffer);
      const sha1Buf = await crypto.subtle.digest('SHA-1', this.buffer);
      const sha256Buf = await crypto.subtle.digest('SHA-256', this.buffer);
      return {
        MD5: md5,
        SHA1: Array.from(new Uint8Array(sha1Buf)).map(b => b.toString(16).padStart(2, '0')).join(''),
        SHA256: Array.from(new Uint8Array(sha256Buf)).map(b => b.toString(16).padStart(2, '0')).join(''),
      };
    }

    parse() {
      if (this.u8.length < 64) throw new Error('File too small to be a valid PE.');
      if (this.readU16(0) !== 0x5a4d) throw new Error('Invalid DOS signature (expected MZ).');

      const eLfanew = this.readU32(0x3c);
      if (eLfanew + 4 > this.u8.length) throw new Error('Invalid PE header offset.');

      const peSig = this.readU32(eLfanew);
      if (peSig !== 0x00004550) throw new Error('Invalid PE signature.');

      const fileHeaderOffset = eLfanew + 4;
      const optionalHeaderOffset = fileHeaderOffset + 20;

      this.dosHeader = {
        e_magic: this.readU16(0),
        e_lfanew: eLfanew,
      };

      this.fileHeader = {
        machine: this.readU16(fileHeaderOffset),
        numberOfSections: this.readU16(fileHeaderOffset + 2),
        timeDateStamp: this.readU32(fileHeaderOffset + 4),
        pointerToSymbolTable: this.readU32(fileHeaderOffset + 8),
        numberOfSymbols: this.readU32(fileHeaderOffset + 12),
        sizeOfOptionalHeader: this.readU16(fileHeaderOffset + 16),
        characteristics: this.readU16(fileHeaderOffset + 18),
      };

      const magic = this.readU16(optionalHeaderOffset);
      this.is64 = magic === 0x20b;

      if (magic !== 0x10b && magic !== 0x20b) {
        throw new Error('Unsupported optional header magic.');
      }

      const oh = optionalHeaderOffset;
      this.optionalHeader = {
        magic,
        addressOfEntryPoint: this.readU32(oh + 16),
        imageBase: this.is64 ? this.readU64(oh + 24) : this.readU32(oh + 28),
        sectionAlignment: this.readU32(oh + (this.is64 ? 32 : 32)),
        fileAlignment: this.readU32(oh + (this.is64 ? 36 : 36)),
        sizeOfImage: this.readU32(oh + (this.is64 ? 56 : 56)),
        sizeOfHeaders: this.readU32(oh + (this.is64 ? 60 : 60)),
        subsystem: this.readU16(oh + (this.is64 ? 68 : 68)),
      };

      const dataDirOffset = oh + (this.is64 ? 112 : 96);
      this.dataDirectories = [];
      for (let i = 0; i < 16; i++) {
        const base = dataDirOffset + i * 8;
        this.dataDirectories.push({
          name: DIRECTORY_NAMES[i] || `DIR_${i}`,
          virtualAddress: this.readU32(base),
          size: this.readU32(base + 4),
        });
      }

      const sectionTableOffset = optionalHeaderOffset + this.fileHeader.sizeOfOptionalHeader;
      this.sections = [];

      for (let i = 0; i < this.fileHeader.numberOfSections; i++) {
        const base = sectionTableOffset + i * 40;
        const nameBytes = this.u8.subarray(base, base + 8);
        let name = '';
        for (let j = 0; j < 8 && nameBytes[j] !== 0; j++) name += String.fromCharCode(nameBytes[j]);

        const virtualSize = this.readU32(base + 8);
        const virtualAddress = this.readU32(base + 12);
        const rawSize = this.readU32(base + 16);
        const rawOffset = this.readU32(base + 20);
        const characteristics = this.readU32(base + 36);

        let sectionData = new Uint8Array(0);
        if (rawSize > 0 && rawOffset < this.u8.length) {
          const end = Math.min(rawOffset + rawSize, this.u8.length);
          sectionData = this.u8.subarray(rawOffset, end);
        }

        const readable = !!(characteristics & IMAGE_SCN_MEM_READ);
        const writable = !!(characteristics & IMAGE_SCN_MEM_WRITE);
        const executable = !!(characteristics & IMAGE_SCN_MEM_EXECUTE);

        this.sections.push({
          name,
          virtualAddress,
          virtualSize,
          rawSize,
          rawOffset,
          characteristics,
          entropy: this.calculateEntropy(sectionData),
          permissions: `${readable ? 'R' : '-'}${writable ? 'W' : '-'}${executable ? 'X' : '-'}`,
          rwx: readable && writable && executable,
        });
      }

      this.imports = this.parseImports();
      this.exports = this.parseExports();
      this.imphash = this.calculateImphash();
      this.suspiciousApis = this.findSuspiciousApis();
      this.hasTls = this.dataDirectories[9].virtualAddress !== 0;
    }

    parseImports() {
      const importDir = this.dataDirectories[1];
      if (!importDir || importDir.virtualAddress === 0) return [];

      const imports = [];
      let offset = this.rvaToOffset(importDir.virtualAddress);
      const ptrSize = this.is64 ? 8 : 4;

      while (offset + 20 <= this.u8.length) {
        const originalFirstThunk = this.is64
          ? Number(this.readU64(offset))
          : this.readU32(offset);
        const nameRva = this.readU32(offset + 12);
        const firstThunk = this.is64
          ? Number(this.readU64(offset + 16))
          : this.readU32(offset + 16);

        if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;

        const dllName = this.readString(this.rvaToOffset(nameRva));
        const thunkRva = originalFirstThunk || firstThunk;
        let thunkOffset = this.rvaToOffset(thunkRva);
        const functions = [];

        while (thunkOffset + ptrSize <= this.u8.length) {
          const entry = this.is64
            ? this.readU64(thunkOffset)
            : this.readU32(thunkOffset);
          if (entry === 0) break;

          const isOrdinal = this.is64
            ? (entry & 0x8000000000000000) !== 0
            : (entry & 0x80000000) !== 0;

          if (isOrdinal) {
            const ordinal = this.is64 ? entry & 0xffff : entry & 0xffff;
            functions.push({ name: `Ordinal_${ordinal}`, ordinal: true });
          } else {
            const hintOffset = this.rvaToOffset(Number(entry & 0xffffffff));
            const funcName = this.readString(hintOffset + 2);
            functions.push({ name: funcName, ordinal: false });
          }
          thunkOffset += ptrSize;
        }

        imports.push({ dll: dllName, functions });
        offset += 20;
      }
      return imports;
    }

    parseExports() {
      const exportDir = this.dataDirectories[0];
      if (!exportDir || exportDir.virtualAddress === 0) return [];

      const base = this.rvaToOffset(exportDir.virtualAddress);
      const numberOfFunctions = this.readU32(base + 20);
      const numberOfNames = this.readU32(base + 24);
      const addressOfFunctions = this.rvaToOffset(this.readU32(base + 28));
      const addressOfNames = this.rvaToOffset(this.readU32(base + 32));
      const addressOfNameOrdinals = this.rvaToOffset(this.readU32(base + 36));

      const exports = [];
      for (let i = 0; i < numberOfNames; i++) {
        const nameRva = this.readU32(addressOfNames + i * 4);
        const ordinal = this.readU16(addressOfNameOrdinals + i * 2);
        const funcRva = this.readU32(addressOfFunctions + ordinal * 4);
        exports.push({
          ordinal,
          rva: funcRva,
          name: this.readString(this.rvaToOffset(nameRva)),
        });
      }

      if (exports.length === 0 && numberOfFunctions > 0) {
        for (let i = 0; i < numberOfFunctions; i++) {
          const funcRva = this.readU32(addressOfFunctions + i * 4);
          if (funcRva !== 0) {
            exports.push({ ordinal: i, rva: funcRva, name: '<NO_NAME>' });
          }
        }
      }
      return exports;
    }

    calculateImphash() {
      const parts = [];
      for (const entry of this.imports) {
        const dll = entry.dll.toLowerCase();
        for (const fn of entry.functions) {
          const func = fn.ordinal ? String(fn.name.replace('Ordinal_', '')).toLowerCase() : fn.name.toLowerCase();
          parts.push(`${dll},${func}`);
        }
      }
      if (parts.length === 0) return '';
      return MD5.hashString(parts.join(','));
    }

    findSuspiciousApis() {
      const found = new Set();
      for (const entry of this.imports) {
        for (const fn of entry.functions) {
          if (SUSPICIOUS_APIS.has(fn.name)) found.add(fn.name);
        }
      }
      return [...found].sort();
    }

    formatTimestamp(ts) {
      if (ts === 0) return 'N/A';
      return new Date(ts * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
    }

    getArchitecture() {
      if (this.fileHeader.machine === 0x14c) return '32-bit (x86)';
      if (this.fileHeader.machine === 0x8664) return '64-bit (x64)';
      return `Unknown (${this.hex(this.fileHeader.machine)})`;
    }

    async buildResult() {
      const hashes = await this.calculateHashes();
      const rwxSections = this.sections.filter(s => s.rwx);

      return {
        fileInfo: {
          fileName: this.fileName,
          fileSize: this.buffer.byteLength,
        },
        hashes,
        imphash: this.imphash,
        dosHeader: {
          e_magic: this.hex(this.dosHeader.e_magic),
          e_lfanew: this.hex(this.dosHeader.e_lfanew),
        },
        ntHeader: {
          signature: this.hex(0x4550),
        },
        fileHeader: {
          machine: this.hex(this.fileHeader.machine),
          numberOfSections: this.fileHeader.numberOfSections,
          timestamp: this.formatTimestamp(this.fileHeader.timeDateStamp),
          characteristics: this.hex(this.fileHeader.characteristics),
        },
        optionalHeader: {
          entryPoint: this.hex(this.optionalHeader.addressOfEntryPoint),
          imageBase: this.hex(this.optionalHeader.imageBase),
          sectionAlignment: this.hex(this.optionalHeader.sectionAlignment),
          fileAlignment: this.hex(this.optionalHeader.fileAlignment),
          sizeOfImage: this.hex(this.optionalHeader.sizeOfImage),
          sizeOfHeaders: this.hex(this.optionalHeader.sizeOfHeaders),
          subsystem: this.optionalHeader.subsystem,
        },
        sections: this.sections,
        imports: this.imports,
        exports: this.exports,
        suspiciousApis: this.suspiciousApis,
        dataDirectories: this.dataDirectories,
        tls: { present: this.hasTls },
        summary: {
          architecture: this.getArchitecture(),
          isGui: this.optionalHeader.subsystem === 2,
          importedDlls: this.imports.length,
          rwxSections: rwxSections.map(s => s.name),
          sectionCount: this.sections.length,
          exportCount: this.exports.length,
        },
      };
    }
  }

  global.PEParser = PEParser;
  global.PEVisionConstants = { SUSPICIOUS_APIS, DIRECTORY_NAMES };
})(typeof window !== 'undefined' ? window : globalThis);
