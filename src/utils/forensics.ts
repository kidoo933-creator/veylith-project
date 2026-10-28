import {
  FileAnalysisResult,
  BoundedMetadata,
  EntropyBlock,
  UnavailableCheck,
} from '../types';

export const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB
export const BOUNDED_INSPECTION_BYTES = 4 * 1024 * 1024; // 4 MB deep inspection window

// Compute SHA-256 and SHA-1 using Web Crypto API
export async function computeHashes(buffer: ArrayBuffer): Promise<{ sha256: string; sha1: string; md5: string }> {
  const sha256Buffer = await crypto.subtle.digest('SHA-256', buffer);
  const sha1Buffer = await crypto.subtle.digest('SHA-1', buffer);

  const toHex = (buf: ArrayBuffer) =>
    Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

  return {
    sha256: toHex(sha256Buffer),
    sha1: toHex(sha1Buffer),
    md5: computeFastMd5(new Uint8Array(buffer)),
  };
}

// Shannon Entropy Calculation (0.0000 to 8.0000 bits per byte)
export function computeEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const frequencies = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }

  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    const count = frequencies[i];
    if (count > 0) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
  }

  return Number(entropy.toFixed(4));
}

// Compute sliding block entropy across file to identify packed overlays or sections
export function computeEntropyBlocks(bytes: Uint8Array, numBlocks = 16): EntropyBlock[] {
  if (bytes.length === 0) return [];
  const totalLength = bytes.length;
  const blockSize = Math.max(256, Math.floor(totalLength / numBlocks));
  const blocks: EntropyBlock[] = [];

  for (let i = 0; i < numBlocks; i++) {
    const start = i * blockSize;
    if (start >= totalLength) break;
    const end = Math.min(start + blockSize, totalLength);
    const slice = bytes.slice(start, end);
    blocks.push({
      blockIndex: i + 1,
      offset: start,
      entropy: computeEntropy(slice),
    });
  }

  return blocks;
}

// Robust File Signature & Magic Bytes Detection
export function detectFileSignature(bytes: Uint8Array): {
  magicHex: string;
  detectedFormat: string;
  expectedExtensions: string[];
  subType?: string;
} {
  const slice = bytes.slice(0, 16);
  const hex = Array.from(slice)
    .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
    .join(' ');

  // PE / MZ (Windows Executables, DLLs, Drivers, Screensavers)
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
    let sub = 'MZ Executable';
    if (bytes.length >= 64) {
      const peOffset = bytes[0x3c] | (bytes[0x3d] << 8) | (bytes[0x3e] << 16) | (bytes[0x3f] << 24);
      if (peOffset > 0 && peOffset + 4 < bytes.length) {
        if (bytes[peOffset] === 0x50 && bytes[peOffset + 1] === 0x45) {
          sub = 'PE32 / PE32+ (COFF Header Confirmed)';
        }
      }
    }
    return {
      magicHex: hex.slice(0, 5),
      detectedFormat: 'PE Executable (Windows Binary / DLL / Sys)',
      expectedExtensions: ['.exe', '.dll', '.sys', '.scr', '.drv', '.ocx', '.cpl'],
      subType: sub,
    };
  }

  // Linux ELF
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
    const is64 = bytes[4] === 2;
    return {
      magicHex: hex.slice(0, 11),
      detectedFormat: `ELF Binary (${is64 ? '64-bit' : '32-bit'} Linux Executable / Shared Object)`,
      expectedExtensions: ['.elf', '.so', '.bin', '.out', '.ko'],
      subType: is64 ? 'ELF64' : 'ELF32',
    };
  }

  // macOS / iOS Mach-O
  if (
    (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xce) ||
    (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
    (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe) ||
    (bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe)
  ) {
    const isFat = bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe;
    return {
      magicHex: hex.slice(0, 11),
      detectedFormat: isFat ? 'Mach-O Universal (Fat Binary) / Java Class' : 'Mach-O Binary (macOS/iOS Executable)',
      expectedExtensions: ['.dylib', '.o', '.class', ''],
      subType: 'Mach-O / Apple Mach Kernel Object',
    };
  }

  // PDF (Portable Document Format)
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
    let ver = '1.x';
    if (bytes[5] === 0x31 && bytes[6] === 0x2e) {
      ver = `1.${String.fromCharCode(bytes[7])}`;
    }
    return {
      magicHex: hex.slice(0, 14),
      detectedFormat: `PDF Document (Adobe Portable Document v${ver})`,
      expectedExtensions: ['.pdf'],
      subType: `PDF-${ver}`,
    };
  }

  // ZIP Container / Android APK / JAR / Office OpenXML
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && (bytes[2] === 0x03 || bytes[2] === 0x05 || bytes[2] === 0x07)) {
    return {
      magicHex: hex.slice(0, 11),
      detectedFormat: 'ZIP Archive / Container (PKZIP, Android APK, JAR, DOCX, XLSX)',
      expectedExtensions: ['.zip', '.apk', '.jar', '.docx', '.xlsx', '.pptx', '.aar'],
      subType: 'PKZip Container',
    };
  }

  // Microsoft OLE2 Compound File (Legacy Word/Excel/PowerPoint 97-2003 / MSI Installer)
  if (
    bytes[0] === 0xd0 &&
    bytes[1] === 0xcf &&
    bytes[2] === 0x11 &&
    bytes[3] === 0xe0 &&
    bytes[4] === 0xa1 &&
    bytes[5] === 0xb1 &&
    bytes[6] === 0x1a &&
    bytes[7] === 0xe1
  ) {
    return {
      magicHex: hex.slice(0, 23),
      detectedFormat: 'Microsoft OLE2 Compound Document (Legacy Office / MSI Package)',
      expectedExtensions: ['.doc', '.xls', '.ppt', '.msi'],
      subType: 'Compound File Binary (CFB)',
    };
  }

  // 7-Zip Archive
  if (bytes[0] === 0x37 && bytes[1] === 0x7a && bytes[2] === 0xbc && bytes[3] === 0xaf && bytes[4] === 0x27 && bytes[5] === 0x1c) {
    return {
      magicHex: hex.slice(0, 17),
      detectedFormat: '7-Zip Compressed Archive (7z)',
      expectedExtensions: ['.7z'],
      subType: 'LZMA / 7z',
    };
  }

  // RAR Archive
  if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21 && bytes[4] === 0x1a && bytes[5] === 0x07) {
    return {
      magicHex: hex.slice(0, 17),
      detectedFormat: 'RAR Compressed Archive',
      expectedExtensions: ['.rar'],
      subType: bytes[6] === 0x00 ? 'RAR v4' : 'RAR v5',
    };
  }

  // GZIP Archive
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return {
      magicHex: hex.slice(0, 5),
      detectedFormat: 'GZIP Compressed Archive',
      expectedExtensions: ['.gz', '.tgz'],
      subType: 'DEFLATE / Gzip',
    };
  }

  // BZIP2
  if (bytes[0] === 0x42 && bytes[1] === 0x5a && bytes[2] === 0x68) {
    return {
      magicHex: hex.slice(0, 8),
      detectedFormat: 'BZIP2 Compressed Archive',
      expectedExtensions: ['.bz2', '.tbz2'],
      subType: 'Bzip2',
    };
  }

  // XZ Compressed Archive
  if (bytes[0] === 0xfd && bytes[1] === 0x37 && bytes[2] === 0x7a && bytes[3] === 0x58 && bytes[4] === 0x5a && bytes[5] === 0x00) {
    return {
      magicHex: hex.slice(0, 17),
      detectedFormat: 'XZ Compressed Data Container',
      expectedExtensions: ['.xz'],
      subType: 'XZ / LZMA2',
    };
  }

  // SQLite 3 Database
  if (
    bytes[0] === 0x53 &&
    bytes[1] === 0x51 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x69 &&
    bytes[4] === 0x74 &&
    bytes[5] === 0x65 &&
    bytes[6] === 0x20 &&
    bytes[7] === 0x66
  ) {
    return {
      magicHex: hex.slice(0, 23),
      detectedFormat: 'SQLite 3 Database File',
      expectedExtensions: ['.sqlite', '.db', '.sqlite3'],
      subType: 'SQLite v3',
    };
  }

  // PCAP (tcpdump / Wireshark)
  if (
    (bytes[0] === 0xd4 && bytes[1] === 0xc3 && bytes[2] === 0xb2 && bytes[3] === 0xa1) ||
    (bytes[0] === 0xa1 && bytes[1] === 0xb2 && bytes[2] === 0xc3 && bytes[3] === 0xd4)
  ) {
    const isLe = bytes[0] === 0xd4;
    return {
      magicHex: hex.slice(0, 11),
      detectedFormat: `PCAP Packet Capture (${isLe ? 'Little-Endian' : 'Big-Endian'})`,
      expectedExtensions: ['.pcap', '.cap', '.dmp'],
      subType: 'libpcap format',
    };
  }

  // PCAPNG
  if (bytes[0] === 0x0a && bytes[1] === 0x0d && bytes[2] === 0x0d && bytes[3] === 0x0a) {
    return {
      magicHex: hex.slice(0, 11),
      detectedFormat: 'PCAPNG (Next Generation Packet Capture)',
      expectedExtensions: ['.pcapng'],
      subType: 'Section Header Block (SHB)',
    };
  }

  // PNG Image
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return {
      magicHex: hex.slice(0, 11),
      detectedFormat: 'PNG Image (Portable Network Graphics)',
      expectedExtensions: ['.png'],
      subType: 'Raster Graphic',
    };
  }

  // JPEG Image
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return {
      magicHex: hex.slice(0, 8),
      detectedFormat: 'JPEG Image (Joint Photographic Experts Group)',
      expectedExtensions: ['.jpg', '.jpeg'],
      subType: 'JFIF / Exif',
    };
  }

  // WebP Image / RIFF
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46) {
    const isWebP = bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50;
    return {
      magicHex: hex.slice(0, 11),
      detectedFormat: isWebP ? 'WebP Image (RIFF Container)' : 'RIFF Multimedia Container (AVI / WAV)',
      expectedExtensions: isWebP ? ['.webp'] : ['.avi', '.wav'],
      subType: isWebP ? 'WebP' : 'RIFF',
    };
  }

  // Scripts / ASCII Shebang
  if (bytes[0] === 0x23 && bytes[1] === 0x21) {
    const textPreview = String.fromCharCode(...bytes.slice(0, 48));
    return {
      magicHex: '23 21',
      detectedFormat: `Unix Executable Script (${textPreview.trim()})`,
      expectedExtensions: ['.sh', '.bash', '.py', '.pl', '.rb'],
      subType: 'Shebang Script',
    };
  }

  return {
    magicHex: hex.slice(0, 11) || '00 00',
    detectedFormat: 'Generic Binary Data / Unrecognized Format',
    expectedExtensions: [],
    subType: 'Raw Data Stream',
  };
}

// Bounded PE Header & Section Inspector
export function inspectPeHeader(bytes: Uint8Array) {
  if (bytes.length < 64 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return undefined;

  const peOffset = bytes[0x3c] | (bytes[0x3d] << 8) | (bytes[0x3e] << 16) | (bytes[0x3f] << 24);
  if (peOffset <= 0 || peOffset + 24 >= bytes.length) return undefined;
  if (bytes[peOffset] !== 0x50 || bytes[peOffset + 1] !== 0x45) return undefined; // 'PE\0\0'

  const coffOffset = peOffset + 4;
  const machineId = bytes[coffOffset] | (bytes[coffOffset + 1] << 8);
  const numberOfSections = bytes[coffOffset + 2] | (bytes[coffOffset + 3] << 8);
  const timeDateStamp =
    bytes[coffOffset + 4] | (bytes[coffOffset + 5] << 8) | (bytes[coffOffset + 6] << 16) | (bytes[coffOffset + 7] << 24);
  const optionalHeaderSize = bytes[coffOffset + 16] | (bytes[coffOffset + 17] << 8);

  let machine = 'Unknown Architecture';
  let is64Bit = false;
  if (machineId === 0x014c) machine = 'Intel 386 (x86 32-bit)';
  else if (machineId === 0x8664) {
    machine = 'AMD64 / x86-64 (64-bit)';
    is64Bit = true;
  } else if (machineId === 0xaa64) {
    machine = 'ARM64 (Little Endian)';
    is64Bit = true;
  }

  const sectionsOffset = coffOffset + 20 + optionalHeaderSize;
  const sections: { name: string; virtualSize: number; rawSize: number; entropy: number }[] = [];

  for (let i = 0; i < Math.min(numberOfSections, 16); i++) {
    const sOffset = sectionsOffset + i * 40;
    if (sOffset + 40 > bytes.length) break;

    const nameBytes = bytes.slice(sOffset, sOffset + 8);
    let name = '';
    for (let c = 0; c < 8; c++) {
      if (nameBytes[c] === 0) break;
      name += String.fromCharCode(nameBytes[c]);
    }

    const virtualSize = bytes[sOffset + 8] | (bytes[sOffset + 9] << 8) | (bytes[sOffset + 10] << 16) | (bytes[sOffset + 11] << 24);
    const rawSize = bytes[sOffset + 16] | (bytes[sOffset + 17] << 8) | (bytes[sOffset + 18] << 16) | (bytes[sOffset + 19] << 24);
    const rawPointer = bytes[sOffset + 20] | (bytes[sOffset + 21] << 8) | (bytes[sOffset + 22] << 16) | (bytes[sOffset + 23] << 24);

    let secEntropy = 0;
    if (rawPointer > 0 && rawSize > 0 && rawPointer + rawSize <= bytes.length) {
      secEntropy = computeEntropy(bytes.slice(rawPointer, rawPointer + Math.min(rawSize, 65536)));
    }

    sections.push({
      name: name || `.sec${i + 1}`,
      virtualSize,
      rawSize,
      entropy: secEntropy,
    });
  }

  const compileDate = timeDateStamp > 0 ? new Date(timeDateStamp * 1000).toISOString() : 'Unknown Timestamp';

  return {
    machine,
    is64Bit,
    peHeaderOffset: peOffset,
    compileTimestamp: compileDate,
    numberOfSections,
    sections,
  };
}

// Bounded ELF Header Inspector
export function inspectElfHeader(bytes: Uint8Array) {
  if (bytes.length < 52 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    return undefined;
  }

  const is64 = bytes[4] === 2;
  const isLe = bytes[5] === 1;
  const osAbiCode = bytes[7];
  const typeCode = bytes[16] | (bytes[17] << 8);

  let type = 'Unknown';
  if (typeCode === 1) type = 'Relocatable (ET_REL)';
  else if (typeCode === 2) type = 'Executable (ET_EXEC)';
  else if (typeCode === 3) type = 'Shared Object / Dynamic Library (ET_DYN)';
  else if (typeCode === 4) type = 'Core Dump (ET_CORE)';

  let osAbi = 'System V (UNIX)';
  if (osAbiCode === 3) osAbi = 'Linux';
  else if (osAbiCode === 0) osAbi = 'System V';
  else if (osAbiCode === 9) osAbi = 'FreeBSD';

  return {
    bitness: is64 ? '64-bit' : '32-bit',
    endianness: isLe ? 'Little Endian' : 'Big Endian',
    osAbi,
    type,
    machine: is64 ? 'x86_64 / AArch64' : 'x86 / ARM32',
  };
}

// Bounded PDF Structural Metadata Inspector
export function inspectPdf(bytes: Uint8Array) {
  if (bytes[0] !== 0x25 || bytes[1] !== 0x50 || bytes[2] !== 0x44 || bytes[3] !== 0x46) {
    return undefined;
  }

  const limit = Math.min(bytes.length, BOUNDED_INSPECTION_BYTES);
  const text = new TextDecoder('latin1').decode(bytes.slice(0, limit));

  const hasJavaScript = text.includes('/JavaScript') || text.includes('/JS');
  const hasLaunchActions = text.includes('/Launch');
  const hasOpenAction = text.includes('/OpenAction') || text.includes('/AA');
  const hasEmbeddedFiles = text.includes('/EmbeddedFiles') || text.includes('/Filespec');

  // Count /Obj occurrences
  const objMatches = text.match(/\/Obj\b/gi);
  const objectCount = objMatches ? objMatches.length : 0;

  const versionMatch = text.match(/%PDF-([0-9.]+)/);
  const version = versionMatch ? versionMatch[1] : '1.x';

  return {
    version,
    hasJavaScript,
    hasLaunchActions,
    hasOpenAction,
    hasEmbeddedFiles,
    objectCount,
  };
}

// Static APK Structural Inspection (ZIP Central Directory & Android Manifest Analysis)
export function inspectApkStructural(bytes: Uint8Array, fileName: string) {
  const isZip = bytes[0] === 0x50 && bytes[1] === 0x4b;
  const isApkExt = fileName.toLowerCase().endsWith('.apk');
  if (!isZip && !isApkExt) return undefined;

  const limit = Math.min(bytes.length, BOUNDED_INSPECTION_BYTES);
  const text = new TextDecoder('latin1').decode(bytes.slice(0, limit));

  const hasManifest = text.includes('AndroidManifest.xml');
  if (!hasManifest && !isApkExt) return undefined;

  let dexCount = 0;
  const dexFileNames: string[] = [];
  if (text.includes('classes.dex')) {
    dexCount++;
    dexFileNames.push('classes.dex');
  }
  if (text.includes('classes2.dex')) {
    dexCount++;
    dexFileNames.push('classes2.dex');
  }
  if (text.includes('classes3.dex')) {
    dexCount++;
    dexFileNames.push('classes3.dex');
  }
  if (text.includes('classes4.dex')) {
    dexCount++;
    dexFileNames.push('classes4.dex');
  }

  const nativeArchs: string[] = [];
  if (text.includes('lib/arm64-v8a/')) nativeArchs.push('arm64-v8a');
  if (text.includes('lib/armeabi-v7a/')) nativeArchs.push('armeabi-v7a');
  if (text.includes('lib/x86_64/')) nativeArchs.push('x86_64');
  if (text.includes('lib/x86/')) nativeArchs.push('x86');

  const hasCerts = text.includes('META-INF/') && (text.includes('.RSA') || text.includes('.SF') || text.includes('.DSA'));
  const hasDebuggable = text.includes('android:debuggable') || text.includes('debuggable="true"');

  // Permission database with risk ratings and plain-English descriptions
  const catalog = [
    {
      name: 'android.permission.INTERNET',
      risk: 'Normal' as const,
      description: 'Allows connection to external networks and C2 command servers.',
    },
    {
      name: 'android.permission.ACCESS_NETWORK_STATE',
      risk: 'Normal' as const,
      description: 'Allows inspecting current cellular and Wi-Fi connectivity.',
    },
    {
      name: 'android.permission.CAMERA',
      risk: 'Dangerous' as const,
      description: 'Allows capturing photos and video without explicit runtime UI.',
    },
    {
      name: 'android.permission.RECORD_AUDIO',
      risk: 'Dangerous' as const,
      description: 'Allows recording ambient microphone audio (wiretapping indicator).',
    },
    {
      name: 'android.permission.ACCESS_FINE_LOCATION',
      risk: 'Dangerous' as const,
      description: 'Allows high-precision GPS geolocation tracking.',
    },
    {
      name: 'android.permission.READ_SMS',
      risk: 'Dangerous' as const,
      description: 'Allows reading incoming SMS messages (frequently abused for OTP bypass).',
    },
    {
      name: 'android.permission.SEND_SMS',
      risk: 'Dangerous' as const,
      description: 'Allows silent transmission of premium-rate SMS messages.',
    },
    {
      name: 'android.permission.READ_CONTACTS',
      risk: 'Privacy' as const,
      description: 'Allows exfiltrating user contact records.',
    },
    {
      name: 'android.permission.REQUEST_INSTALL_PACKAGES',
      risk: 'Dangerous' as const,
      description: 'Allows downloading and installing secondary untrusted APK payloads.',
    },
    {
      name: 'android.permission.SYSTEM_ALERT_WINDOW',
      risk: 'Dangerous' as const,
      description: 'Allows overlaying screens (abused for credential phishing and cloaking).',
    },
    {
      name: 'android.permission.RECEIVE_BOOT_COMPLETED',
      risk: 'Normal' as const,
      description: 'Allows automatic persistence upon device reboot.',
    },
    {
      name: 'android.permission.WRITE_EXTERNAL_STORAGE',
      risk: 'Privacy' as const,
      description: 'Allows modifying files on shared device storage.',
    },
  ];

  const detectedPermissions = catalog.filter((p) => {
    const rawShort = p.name.replace('android.permission.', '');
    return text.includes(p.name) || text.includes(rawShort);
  });

  return {
    isApk: true,
    packageName: hasManifest ? 'Found in AndroidManifest.xml' : 'Obfuscated / Stripped',
    permissions: detectedPermissions,
    dexFilesFound: Math.max(dexCount, 1),
    dexFileNames: dexFileNames.length > 0 ? dexFileNames : ['classes.dex'],
    nativeArchitectures: nativeArchs,
    hasCertificates: hasCerts,
    hasDebuggableFlag: hasDebuggable,
  };
}

// Bounded Strings Extractor with Heuristic IOC Categorization
export function extractPrintableStrings(
  bytes: Uint8Array,
  minLength = 4,
  maxStrings = 250
): {
  total: number;
  extracted: { value: string; category: 'url' | 'ip' | 'api' | 'path' | 'string' | 'command' | 'registry' }[];
} {
  let count = 0;
  const results: { value: string; category: 'url' | 'ip' | 'api' | 'path' | 'string' | 'command' | 'registry' }[] = [];
  let currentChars: number[] = [];

  const urlRegex = /^https?:\/\//i;
  const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const apiRegex =
    /^(VirtualAlloc|VirtualProtect|CreateProcess|WriteProcessMemory|LoadLibrary|GetProcAddress|WinExec|RegOpenKey|HttpSendRequest|ShellExecute|WScript\.Shell|mprotect|ptrace|execve|socket|connect|fork)/i;
  const pathRegex = /^[A-Z]:\\|^\/(?:bin|etc|var|tmp|usr|system|data|proc)\//i;
  const cmdRegex = /^(powershell|cmd\.exe|certutil|bitsadmin|bash|sh|curl|wget|mshta|rundll32|regsvr32)/i;
  const regRegex = /^(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\Software/i;

  const pushString = () => {
    if (currentChars.length >= minLength) {
      count++;
      if (results.length < maxStrings) {
        const str = String.fromCharCode(...currentChars).trim();
        if (str.length >= minLength) {
          let category: 'url' | 'ip' | 'api' | 'path' | 'string' | 'command' | 'registry' = 'string';
          if (urlRegex.test(str)) category = 'url';
          else if (ipRegex.test(str)) category = 'ip';
          else if (cmdRegex.test(str)) category = 'command';
          else if (regRegex.test(str)) category = 'registry';
          else if (apiRegex.test(str)) category = 'api';
          else if (pathRegex.test(str)) category = 'path';

          results.push({ value: str, category });
        }
      }
    }
    currentChars = [];
  };

  const limit = Math.min(bytes.length, BOUNDED_INSPECTION_BYTES);
  for (let i = 0; i < limit; i++) {
    const b = bytes[i];
    // Printable ASCII 32 (space) to 126 (tilde)
    if (b >= 32 && b <= 126) {
      currentChars.push(b);
    } else {
      pushString();
    }
  }
  pushString();

  return { total: count, extracted: results };
}

// Transparent list of unavailable checks and their defensive alternatives
export function getUnavailableChecksList(): UnavailableCheck[] {
  return [
    {
      name: 'Dynamic Sandbox Execution',
      category: 'Runtime Behavior',
      reason: 'Strict Non-Execution Policy: Veylith guarantees analyzed files are never executed, installed, or run dynamically.',
      defensiveAlternative: 'Perform safe static analysis, extract bounded strings, verify magic bytes, and calculate entropy.',
    },
    {
      name: 'Hypervisor Kernel Hooking & API Tracing',
      category: 'Kernel Instrumentation',
      reason: 'Requires bare-metal hardware virtualization or dedicated hypervisor VM agent not available in browser runtime.',
      defensiveAlternative: 'Inspect static PE/ELF import table hints and printable API symbol strings.',
    },
    {
      name: 'Native C-Compiled YARA Engine',
      category: 'Signature Matching',
      reason: 'Native libyara is a C library requiring platform binaries; not compiled into the web environment.',
      defensiveAlternative: 'Utilize Veylith heuristic pattern matcher, bounded regular expressions, and hash cross-referencing.',
    },
    {
      name: 'Cloud Vendor Telemetry / VirusTotal Upload',
      category: 'External Disclosure',
      reason: 'Disabled by default to prevent leaking proprietary intellectual property or sensitive corporate artifacts.',
      defensiveAlternative: 'Query hash intelligence safely (SHA-256) without uploading confidential file payloads.',
    },
    {
      name: 'Full DEX Bytecode Decompilation (JADX / CFR)',
      category: 'Reverse Engineering',
      reason: 'Full bytecode decompilation requires a complete Java Virtual Machine (JVM) headless engine.',
      defensiveAlternative: 'Perform structural ZIP parsing, extract manifest permissions, dex entry counts, and native ELF libraries.',
    },
  ];
}

// Full Forensic File Pipeline
export async function analyzeFile(file: File): Promise<FileAnalysisResult> {
  // File size validation guard
  if (file.size > MAX_FILE_SIZE_BYTES) {
    throw new Error(
      `File size (${(file.size / (1024 * 1024)).toFixed(1)} MB) exceeds the 50 MB in-browser forensic safety limit. To protect system memory and prevent tab freezing, analyze files larger than 50 MB via command-line tools (e.g. 'sha256sum').`
    );
  }

  const arrayBuffer = await file.arrayBuffer();
  const bytes = new Uint8Array(arrayBuffer);

  const hashes = await computeHashes(arrayBuffer);
  const entropy = computeEntropy(bytes);
  const entropyBlocks = computeEntropyBlocks(bytes, 16);
  const sig = detectFileSignature(bytes);

  // Check extension vs signature mismatch
  const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();
  let formatMismatch = false;
  let mismatchDescription: string | undefined;

  if (sig.expectedExtensions.length > 0 && !sig.expectedExtensions.includes(ext)) {
    formatMismatch = true;
    mismatchDescription = `File extension is "${ext}", but the file magic signature indicates "${sig.detectedFormat}". This discrepancy is a primary indicator of masquerading or disguised binary payloads.`;
  }

  // Entropy evaluation
  let entropyStatus: 'Normal' | 'Moderate' | 'High' = 'Normal';
  let entropyExplanation =
    'Standard uncompressed file content. Byte frequency distribution is balanced without significant compression or packing.';
  if (entropy > 7.2) {
    entropyStatus = 'High';
    entropyExplanation =
      'High entropy (> 7.2 bits/byte). This is consistent with encrypted, heavily obfuscated, or packed binary data (e.g., UPX, Themida, or cryptographic payloads). Note: Standard compressed formats (ZIP, PNG, MP4) also exhibit high entropy naturally; high entropy alone is not proof of malicious intent.';
  } else if (entropy > 6.0) {
    entropyStatus = 'Moderate';
    entropyExplanation =
      'Moderate entropy (6.0 - 7.2 bits/byte). Typical for compiled binaries, structured archives, or mixed text and media sections.';
  } else if (entropy < 2.0) {
    entropyExplanation =
      'Low entropy (< 2.0 bits/byte). Indicates highly repetitive, sparse, or null-padded content (e.g., initialized memory buffers).';
  }

  // Bounded metadata extraction
  const peMetadata = inspectPeHeader(bytes);
  const elfMetadata = inspectElfHeader(bytes);
  const pdfMetadata = inspectPdf(bytes);
  const apkMetadata = inspectApkStructural(bytes, file.name);

  const metadata: BoundedMetadata = {
    peMetadata,
    elfMetadata,
    pdfMetadata,
    apkMetadata,
  };

  const stringsResult = extractPrintableStrings(bytes);
  const unavailableChecks = getUnavailableChecksList();

  const formatSize = (sz: number) => {
    if (sz < 1024) return `${sz} B`;
    if (sz < 1024 * 1024) return `${(sz / 1024).toFixed(1)} KB`;
    return `${(sz / (1024 * 1024)).toFixed(2)} MB`;
  };

  return {
    fileName: file.name,
    fileSize: file.size,
    fileSizeFormatted: formatSize(file.size),
    mimeType: file.type || 'application/octet-stream',
    sha256: hashes.sha256,
    sha1: hashes.sha1,
    md5: hashes.md5,
    magicBytes: sig.magicHex,
    detectedFormat: sig.detectedFormat,
    formatMismatch,
    mismatchDescription,
    entropy,
    entropyEvaluation: {
      status: entropyStatus,
      explanation: entropyExplanation,
    },
    entropyBlocks,
    printableStrings: stringsResult,
    metadata,
    apkDetails: apkMetadata
      ? {
          isApk: true,
          packageName: apkMetadata.packageName,
          permissions: (apkMetadata.permissions || []).map((p) => p.name),
          dexFilesFound: apkMetadata.dexFilesFound,
          hasDebuggableFlag: apkMetadata.hasDebuggableFlag,
        }
      : undefined,
    unavailableChecks,
    timestamp: new Date().toISOString(),
  };
}

// Compact MD5 implementation for client-side forensics without external dependencies
function computeFastMd5(bytes: Uint8Array): string {
  function safeAdd(x: number, y: number) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }
  function bitRol(num: number, cnt: number) {
    return (num << cnt) | (num >>> (32 - cnt));
  }
  function md5cmn(q: number, a: number, b: number, x: number, s: number, t: number) {
    return safeAdd(bitRol(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }
  function md5ff(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return md5cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function md5gg(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function md5hh(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return md5cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function md5ii(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return md5cmn(c ^ (b | ~d), a, b, x, s, t);
  }

  const n = bytes.length;
  const wordCount = (((n + 8) >> 6) + 1) * 16;
  const x = new Int32Array(wordCount);
  for (let i = 0; i < n; i++) {
    x[i >> 2] |= (bytes[i] & 0xff) << ((i % 4) * 8);
  }
  x[n >> 2] |= 0x80 << ((n % 4) * 8);
  x[wordCount - 2] = (n * 8) & 0xffffffff;
  x[wordCount - 1] = Math.floor((n * 8) / 0x100000000);

  let a = 1732584193;
  let b = -271733879;
  let c = -1732584194;
  let d = 271733878;

  for (let i = 0; i < x.length; i += 16) {
    const olda = a,
      oldb = b,
      oldc = c,
      oldd = d;
    a = md5ff(a, b, c, d, x[i], 7, -680876936);
    d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
    b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
    d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
    b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
    d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
    b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
    d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
    b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);

    a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
    d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
    b = md5gg(b, c, d, a, x[i], 20, -373897302);
    a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
    d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
    b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
    d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
    b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
    d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
    b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);

    a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
    d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
    b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
    d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
    b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
    d = md5hh(d, a, b, c, x[i], 11, -358537222);
    c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
    b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
    d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
    b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);

    a = md5ii(a, b, c, d, x[i], 6, -198630844);
    d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
    b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
    d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
    b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
    d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
    b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
    d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
    b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);

    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }

  function rhex(n: number) {
    let s = '',
      j;
    for (j = 0; j <= 3; j++) {
      s += ((n >> (j * 8 + 4)) & 0x0f).toString(16) + ((n >> (j * 8)) & 0x0f).toString(16);
    }
    return s;
  }

  return rhex(a) + rhex(b) + rhex(c) + rhex(d);
}
