import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeEntropy,
  computeEntropyBlocks,
  detectFileSignature,
  extractPrintableStrings,
  getUnavailableChecksList,
  inspectPeHeader,
  inspectElfHeader,
  inspectPdf,
  inspectApkStructural,
  MAX_FILE_SIZE_BYTES,
} from '../src/utils/forensics.ts';

describe('Veylith File Forensics Engine', () => {
  // 1. File Signatures & Magic Bytes Detection
  describe('File Format Detection', () => {
    test('detects PDF format accurately', () => {
      const bytes = new TextEncoder().encode('%PDF-1.7\n%obj...');
      const sig = detectFileSignature(bytes);
      assert.ok(sig.detectedFormat.includes('PDF'));
      assert.strictEqual(sig.subType, 'PDF-1.7');
      assert.ok(sig.expectedExtensions.includes('.pdf'));
    });

    test('detects ZIP / APK format accurately', () => {
      const bytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
      const sig = detectFileSignature(bytes);
      assert.ok(sig.detectedFormat.includes('ZIP'));
      assert.ok(sig.expectedExtensions.includes('.apk'));
      assert.ok(sig.expectedExtensions.includes('.zip'));
    });

    test('detects PE Windows executable', () => {
      // Minimal MZ header with PE signature offset at 0x3c
      const bytes = new Uint8Array(128);
      bytes[0] = 0x4d; // 'M'
      bytes[1] = 0x5a; // 'Z'
      bytes[0x3c] = 0x40; // PE offset at byte 64
      bytes[0x40] = 0x50; // 'P'
      bytes[0x41] = 0x45; // 'E'
      const sig = detectFileSignature(bytes);
      assert.ok(sig.detectedFormat.includes('PE'));
      assert.ok(sig.expectedExtensions.includes('.exe'));
      assert.ok(sig.expectedExtensions.includes('.dll'));
    });

    test('detects Linux ELF 64-bit binary', () => {
      const bytes = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
      const sig = detectFileSignature(bytes);
      assert.ok(sig.detectedFormat.includes('ELF Binary'));
      assert.strictEqual(sig.subType, 'ELF64');
      assert.ok(sig.expectedExtensions.includes('.elf'));
    });

    test('detects SQLite 3 Database', () => {
      const header = 'SQLite format 3\0';
      const bytes = new TextEncoder().encode(header);
      const sig = detectFileSignature(bytes);
      assert.ok(sig.detectedFormat.includes('SQLite 3'));
      assert.ok(sig.expectedExtensions.includes('.sqlite'));
    });

    test('detects PCAP little-endian format', () => {
      const bytes = new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00]);
      const sig = detectFileSignature(bytes);
      assert.ok(sig.detectedFormat.includes('PCAP Packet Capture'));
      assert.ok(sig.expectedExtensions.includes('.pcap'));
    });

    test('detects PCAPNG next generation format', () => {
      const bytes = new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a, 0x14, 0x00, 0x00, 0x00]);
      const sig = detectFileSignature(bytes);
      assert.ok(sig.detectedFormat.includes('PCAPNG'));
      assert.ok(sig.expectedExtensions.includes('.pcapng'));
    });

    test('handles empty file (0 bytes) gracefully without crashing', () => {
      const bytes = new Uint8Array(0);
      const sig = detectFileSignature(bytes);
      assert.ok(sig.detectedFormat.includes('Empty File'));
      assert.strictEqual(sig.subType, 'Zero-byte Payload');
    });
  });

  // 2. Shannon Entropy Math
  describe('Shannon Entropy Calculation', () => {
    test('calculates 0 entropy for uniform single-byte buffer', () => {
      const bytes = new Uint8Array(1024).fill(0xaa);
      const entropy = computeEntropy(bytes);
      assert.strictEqual(entropy, 0);
    });

    test('calculates 0 entropy for empty buffer', () => {
      const bytes = new Uint8Array(0);
      assert.strictEqual(computeEntropy(bytes), 0);
    });

    test('calculates high entropy (~8.0) for uniformly distributed pseudo-random bytes', () => {
      const bytes = new Uint8Array(256 * 10);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = i % 256;
      }
      const entropy = computeEntropy(bytes);
      assert.strictEqual(entropy, 8.0);
    });

    test('computes sliding entropy blocks across file', () => {
      const bytes = new Uint8Array(2048);
      bytes.fill(0x00, 0, 1024); // first half low entropy
      for (let i = 1024; i < 2048; i++) bytes[i] = i % 256; // second half high entropy

      const blocks = computeEntropyBlocks(bytes, 4);
      assert.strictEqual(blocks.length, 4);
      assert.strictEqual(blocks[0].entropy, 0);
      assert.ok(blocks[2].entropy > 7.0);
    });
  });

  // 3. Printable Strings & IOC Classification
  describe('Printable Strings Extraction', () => {
    test('extracts and categorizes URLs, IPs, Windows APIs, and paths', () => {
      const text =
        'Benign header\x00https://c2.evil-corp.com/beacon\x00192.168.1.100\x00VirtualAlloc\x00C:\\Windows\\System32\\cmd.exe\x00HKLM\\Software\\Microsoft\x00';
      const bytes = new TextEncoder().encode(text);
      const result = extractPrintableStrings(bytes, 4, 100);

      const categories = result.extracted.map((s) => s.category);
      assert.ok(categories.includes('url'));
      assert.ok(categories.includes('ip'));
      assert.ok(categories.includes('api'));
      assert.ok(categories.includes('path'));
      assert.ok(categories.includes('registry'));

      const urlItem = result.extracted.find((s) => s.category === 'url');
      assert.strictEqual(urlItem?.value, 'https://c2.evil-corp.com/beacon');
    });

    test('respects minLength threshold', () => {
      const text = 'a\x00ab\x00abc\x00abcd\x00';
      const bytes = new TextEncoder().encode(text);
      const result = extractPrintableStrings(bytes, 4, 50);
      assert.strictEqual(result.extracted.length, 1);
      assert.strictEqual(result.extracted[0].value, 'abcd');
    });
  });

  // 4. Safety Guardrails & Non-Execution
  describe('Safety & Defensive Limitations', () => {
    test('enforces 50 MB safety threshold', () => {
      assert.strictEqual(MAX_FILE_SIZE_BYTES, 50 * 1024 * 1024);
    });

    test('declares unavailable checks transparently', () => {
      const checks = getUnavailableChecksList();
      assert.ok(checks.length >= 4);
      assert.ok(checks.some((c) => c.name.includes('Dynamic Sandbox Execution')));
      assert.ok(checks.some((c) => c.reason.includes('Non-Execution Policy')));
    });
  });
});
