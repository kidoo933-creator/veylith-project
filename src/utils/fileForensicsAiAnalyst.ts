import {
  FileAnalysisResult,
  InvestigationSimpleReport,
  SimpleFindingItem,
  PrioritizedNextStep,
} from '../types';
import { classifyFindingConfidence } from './aiEvidenceGrounding';

export const FILE_FORENSICS_DISCLAIMER =
  'Forensic findings are derived from static binary inspection, structural metadata, and byte entropy. Static analysis identifies indicators and anomalies without executing the binary in a dynamic sandbox.';

/**
 * Deterministic cybersecurity analyst engine for File Forensics.
 * Generates an executive-level, human-understandable report (Simple Results)
 * from actual static file telemetry.
 */
export function generateFileForensicsSimpleReport(
  fileResult: FileAnalysisResult
): InvestigationSimpleReport {
  const fileName = fileResult.fileName || 'Investigated File';
  const findings: SimpleFindingItem[] = [];
  const whatWasDiscovered: string[] = [];
  const whatIsWorkingWell: string[] = [];
  const limitations: string[] = [];

  const {
    fileSizeFormatted,
    mimeType,
    sha256,
    magicBytes,
    detectedFormat,
    formatMismatch,
    mismatchDescription,
    entropy,
    entropyEvaluation,
    printableStrings,
    metadata,
    apkDetails,
    unavailableChecks,
  } = fileResult;

  // 1. FACTUAL DISCOVERIES
  whatWasDiscovered.push(
    `File size is ${fileSizeFormatted} (${fileResult.fileSize} bytes) with detected format "${detectedFormat}" (magic bytes: ${magicBytes || 'None'}).`
  );
  whatWasDiscovered.push(`Cryptographic SHA-256 hash: ${sha256}`);
  whatWasDiscovered.push(
    `Overall byte entropy measured at ${entropy.toFixed(2)} / 8.00 (${entropyEvaluation.status} randomness).`
  );

  if (printableStrings.extracted.length > 0) {
    const urls = printableStrings.extracted.filter((s) => s.category === 'url');
    const ips = printableStrings.extracted.filter((s) => s.category === 'ip');
    const apis = printableStrings.extracted.filter((s) => s.category === 'api');
    const commands = printableStrings.extracted.filter((s) => s.category === 'command');

    whatWasDiscovered.push(
      `Extracted ${printableStrings.total} printable strings, including ${urls.length} URLs, ${ips.length} IP references, ${apis.length} API symbols, and ${commands.length} command strings.`
    );
  }

  // 2. POSITIVE HIGHLIGHTS (What is working well)
  if (!formatMismatch) {
    whatIsWorkingWell.push(
      `File extension matches internal magic byte structure (${detectedFormat}). No extension masquerading detected.`
    );
  }

  if (entropyEvaluation.status === 'Normal') {
    whatIsWorkingWell.push(
      `Byte entropy is normal (${entropy.toFixed(2)}/8.0). Data does not appear artificially packed, compressed, or encrypted.`
    );
  }

  if (!apkDetails?.hasDebuggableFlag && apkDetails?.isApk) {
    whatIsWorkingWell.push('Android package does not have debugging mode enabled in production manifest.');
  }

  // 3. SECURITY CONCERNS & FOUR-PILLAR TRANSLATIONS

  // (A) Format Mismatch / Disguised File Extension
  if (formatMismatch) {
    findings.push({
      id: 'fnd-file-mismatch',
      title: 'Disguised File Format (Extension Masquerading)',
      category: 'Binary & Static Forensics',
      severity: detectedFormat.includes('Executable') ? 'Critical' : 'High',
      severityExplanation: detectedFormat.includes('Executable')
        ? 'High-risk deception technique: Executable machine code disguised as a document indicates active evasion intent.'
        : 'The declared file extension conflicts with the true internal binary signature.',
      confidence: 'Confirmed',
      whatObserved: mismatchDescription || `The file name implies one format, but header magic bytes indicate "${detectedFormat}".`,
      whatThisMeans:
        'The file is pretending to be something it is not. While the extension makes it look like a regular document or image, the operating system or application will recognize its true format under the surface.',
      potentialRisk:
        'Users or security controls that rely solely on file extensions can be tricked into opening what appears to be an innocent file, which secretly triggers dangerous actions.',
      possibleAttackScenario:
        'An attacker emails an "Urgent_Invoice.pdf" attachment. When the recipient double-clicks it, the operating system ignores the .pdf extension and executes native machine code directly on the host.',
      howToPreventIt:
        'Configure email and web gateways to inspect binary magic bytes (file headers) rather than trusting extensions. Ensure endpoint file associations do not automatically execute mismatched formats.',
      technicalDetails: `File Name: ${fileName} • Declared MIME: ${mimeType} • Magic Bytes: ${magicBytes} • Identified Format: ${detectedFormat}`,
      remediationGuide: {
        detectedTechnology: 'YARA / File Inspection',
        configSnippet: `rule Masqueraded_Executable_Binary {\n  meta:\n    description = "Detects binary executable magic header disguised with document extension"\n    author = "Veylith DFIR"\n  strings:\n    $mz = { 4D 5A }\n  condition:\n    $mz at 0\n}`,
        configLocation: '/etc/yara/rules/masquerading.yar',
        verificationCommand: `file --mime-type "${fileName}" && sha256sum "${fileName}"`,
        documentationUrl: 'https://attack.mitre.org/techniques/T1036/003/',
        thirdPartyHostedNote: 'Quarantine immediately. Configure secure email gateways and endpoint policies (WDAC/AppLocker) to block binary execution from non-standard directories.',
      },
    });
  }

  // (B) High Entropy / Packed Data
  if (entropyEvaluation.status === 'High') {
    findings.push({
      id: 'fnd-file-entropy-high',
      title: 'High Byte Entropy (Likely Packed or Encrypted Code)',
      category: 'Binary & Static Forensics',
      severity: 'Medium',
      severityExplanation:
        'Elevated entropy indicates compressed or encrypted data sections, frequently used by packers to evade signature scanners.',
      confidence: 'Inferred',
      whatObserved: `Overall entropy is ${entropy.toFixed(2)} / 8.0, exceeding the high randomness threshold of 7.0.`,
      whatThisMeans:
        'Imagine a puzzle where all the pieces have been thoroughly scrambled. High entropy means the bytes inside this file are uniformly randomized, which occurs when data is encrypted, compressed, or packed.',
      potentialRisk:
        'Legitimate software usually contains readable text, instructions, and standard headers. Malware authors often pack their code to hide malicious strings and commands from antivirus scanners until runtime.',
      possibleAttackScenario:
        'A threat actor uses a custom packer (crypter) to wrap a remote access Trojan. Antivirus scanners reading the file on disk cannot recognize known malware signatures until the payload unpacks itself in memory.',
      howToPreventIt:
        'Submit the file to a secure sandbox for dynamic memory analysis to capture unpacked payloads. Block unknown packed binaries from executing in sensitive organizational environments.',
      technicalDetails: `Calculated Shannon Entropy: ${entropy.toFixed(4)} • Evaluation: ${entropyEvaluation.explanation}`,
      remediationGuide: {
        detectedTechnology: 'Static Triage',
        configSnippet: `# AppLocker Path Rule: Block unverified executables in AppData/Temp\n<FileRule Action="Deny" User="Everyone" Path="%APPDATA%\\*">\n  <Conditions>\n    <FileHashCondition ... />\n  </Conditions>\n</FileRule>`,
        configLocation: 'Group Policy Management > Windows Settings > AppLocker',
        verificationCommand: `python3 -c "import math, sys; d=open('${fileName}','rb').read(); l=len(d); print('Entropy:', round(sum(-p*math.log2(p) for p in [d.count(bytes([b]))/l for b in set(d)]), 4))"`,
        documentationUrl: 'https://attack.mitre.org/techniques/T1027/002/',
        thirdPartyHostedNote: 'Correlate high entropy with PE section names (.upx, .themida, .vmp) and low import count before concluding malicious intent.',
      },
    });
  }

  // (C) Suspicious API Calls / Commands in Strings
  const injectionApis = printableStrings.extracted.filter((s) =>
    ['VirtualAlloc', 'CreateRemoteThread', 'WriteProcessMemory', 'ShellExecute', 'WinExec', 'OpenProcess'].some(
      (api) => s.value.toLowerCase().includes(api.toLowerCase())
    )
  );

  if (injectionApis.length > 0) {
    findings.push({
      id: 'fnd-file-process-injection',
      title: 'Process Injection & Memory Manipulation API References',
      category: 'Binary & Static Forensics',
      severity: 'High',
      severityExplanation:
        'APIs that allocate memory in remote processes and create threads are primary building blocks for stealthy process hollowing and code injection.',
      confidence: 'Confirmed',
      whatObserved: `Identified system API strings associated with process injection: ${injectionApis.map((a) => a.value).join(', ')}.`,
      whatThisMeans:
        'The file contains references to internal operating system functions designed to inject code into other running programs or start hidden background tasks.',
      potentialRisk:
        'If executed, the program could hijack a legitimate, trusted system process (like explorer.exe or svchost.exe) and run unauthorized code inside it without raising suspicion.',
      possibleAttackScenario:
        'Malware uses VirtualAlloc to prepare memory, WriteProcessMemory to insert malicious instructions into a trusted background service, and CreateRemoteThread to execute the payload stealthily.',
      howToPreventIt:
        'Enforce Endpoint Detection and Response (EDR) behavioral monitoring to detect cross-process memory tampering. Block untrusted binaries from obtaining debug or process-write privileges.',
      technicalDetails: `Extracted Injection APIs: ${injectionApis.map((a) => a.value).join(', ')}`,
    });
  }

  // (D) APK Dangerous Permissions
  if (apkDetails?.isApk && metadata?.apkMetadata?.permissions) {
    const dangerousPerms = metadata.apkMetadata.permissions.filter(
      (p) => p.risk === 'Dangerous' || p.risk === 'Privacy'
    );

    if (dangerousPerms.length > 0) {
      findings.push({
        id: 'fnd-apk-permissions',
        title: `Android Application Requests ${dangerousPerms.length} High-Risk Permission(s)`,
        category: 'Binary & Static Forensics',
        severity: 'Medium',
        severityExplanation:
          'Dangerous permissions grant access to private personal data (SMS, microphone, background location) or privileged system operations.',
        confidence: 'Confirmed',
        whatObserved: `Manifest declares high-risk permissions: ${dangerousPerms.map((p) => p.name).join(', ')}.`,
        whatThisMeans:
          'When installed on an Android device, this app asks for permission to access sensitive hardware or personal data that standard applications rarely require.',
        potentialRisk:
          'An application with these permissions could intercept private text messages (such as two-factor authentication codes), record surrounding audio, or install arbitrary secondary packages.',
        possibleAttackScenario:
          'A malicious banking Trojan disguised as an authentication tool requests READ_SMS to steal one-time bank passcodes, and SYSTEM_ALERT_WINDOW to draw fake login screens over banking apps.',
        howToPreventIt:
          'Follow the principle of least privilege. Remove any permissions that are not strictly necessary for core application functionality, and require explicit runtime consent.',
        technicalDetails: `Declared Dangerous Permissions:\n${dangerousPerms.map((p) => `• ${p.name}: ${p.description}`).join('\n')}`,
      });
    }

    if (apkDetails.hasDebuggableFlag) {
      findings.push({
        id: 'fnd-apk-debuggable',
        title: 'Android Application is Marked as Debuggable (android:debuggable="true")',
        category: 'Binary & Static Forensics',
        severity: 'Medium',
        severityExplanation:
          'Leaving debuggable mode enabled in production exposes application internal memory and variables to local debugging tools.',
        confidence: 'Confirmed',
        whatObserved: 'The AndroidManifest.xml contains android:debuggable="true".',
        whatThisMeans:
          'The application was compiled with developer testing tools left turned on, allowing anyone with device access to connect a debugger.',
        potentialRisk:
          'An attacker or malicious software on the same device can attach to the app, inspect memory, dump encryption keys, and manipulate runtime behavior.',
        possibleAttackScenario:
          'An adversary connects the device via ADB (Android Debug Bridge), attaches a debugger to the running app, and dumps memory tokens and user credentials stored in variables.',
        howToPreventIt:
          'Set `android:debuggable="false"` in the release build configuration within Android Studio / build.gradle before distributing the application.',
        technicalDetails: 'Manifest setting: android:debuggable="true"',
      });
    }

    if (metadata?.apkMetadata?.hasZipSlipTraversal) {
      findings.push({
        id: 'fnd-archive-zipslip',
        title: 'Zip Slip Archive Directory Traversal Indicator',
        category: 'Binary & Static Forensics',
        severity: 'High',
        severityExplanation:
          'Archive entry names contain relative directory traversal sequences ("../" or "..\\") designed to escape extraction boundaries.',
        confidence: 'Confirmed',
        whatObserved: 'Internal archive entry names contain path traversal sequences ("../" or "..\\").',
        whatThisMeans:
          'The archive contains files with paths engineered to break out of the intended extraction folder and overwrite files in parent directories.',
        potentialRisk:
          'If extracted by vulnerable unarchiving software, files can overwrite system binaries, startup scripts, or configuration files.',
        possibleAttackScenario:
          'An attacker constructs an archive with "../../../../etc/cron.d/malicious" to achieve remote code execution upon extraction.',
        howToPreventIt:
          'Enforce strict path canonicalization during extraction, verifying that destination paths are subdirectories of the extraction root.',
        technicalDetails: `Archive: ${fileName} • Traversal detected in internal file entry headers`,
        remediationGuide: {
          detectedTechnology: 'Archive Security',
          configSnippet: '// Secure extraction in Node.js / Python:\nconst targetPath = path.resolve(destDir, entryName);\nif (!targetPath.startsWith(path.resolve(destDir) + path.sep)) {\n  throw new Error("Zip Slip path traversal blocked: " + entryName);\n}',
          configLocation: 'Archive Ingestion & Decompression Filter',
          verificationCommand: `tar -tvf "${fileName}" 2>&1 | grep -E "\\.\\./|\\.\\.\\\\" || unzip -l "${fileName}" | grep -E "\\.\\./|\\.\\.\\\\"`,
          documentationUrl: 'https://snyk.io/research/zip-slip-vulnerability',
        },
      });
    }
  }

  const isZeroByte = fileResult.fileSize === 0;

  // (E) Zero-Byte File Check or Clean File Baseline
  if (isZeroByte) {
    findings.push({
      id: 'fnd-file-empty',
      title: 'Empty Artifact (0 Bytes): Inconclusive Static Analysis',
      category: 'Binary & Static Forensics',
      severity: 'Informational',
      severityExplanation:
        'A zero-byte file contains no data payload, file headers, or executable instructions to inspect.',
      confidence: 'Confirmed',
      whatObserved: `File "${fileName}" has a recorded length of 0 bytes.`,
      whatThisMeans:
        'The file is entirely empty. There is no binary content, magic bytes, or metadata available to evaluate.',
      potentialRisk:
        'Zero-byte files frequently result from interrupted downloads, failed exfiltration attempts, or placeholder marker files created by automated tools.',
      possibleAttackScenario:
        'Some malware families touch empty lockfiles or marker files on disk to record infected host state, or an attacker may touch files to test write permissions.',
      howToPreventIt:
        'Re-acquire the artifact from the source system to verify that the file was not corrupted or truncated during network acquisition.',
      technicalDetails: `SHA-256: ${sha256} • File Size: 0 bytes • Format: ${detectedFormat}`,
    });
  } else if (findings.length === 0) {
    findings.push({
      id: 'fnd-file-baseline',
      title: 'Static Inspection Baseline Satisfied',
      category: 'Binary & Static Forensics',
      severity: 'Informational',
      severityExplanation:
        'All tested static markers (magic bytes, entropy distribution, structure) align with expected standard behavior.',
      confidence: 'Confirmed',
      whatObserved: `File "${fileName}" exhibited expected magic bytes (${magicBytes}), normal entropy (${entropy.toFixed(2)}), and no high-risk injection strings.`,
      whatThisMeans:
        'Initial static examination revealed no obvious deceptive structures or packed malware signatures.',
      potentialRisk:
        'No immediate static risk detected. However, sophisticated zero-day malware or clean documents with macro vulnerabilities may still require behavioral execution testing.',
      possibleAttackScenario:
        'Living-off-the-land techniques or legitimate binaries misused for unintended purposes cannot always be identified by static heuristics alone.',
      howToPreventIt:
        'Maintain defense-in-depth endpoint security, verify digital signatures from trusted software vendors, and employ sandbox detonation for untrusted files.',
      technicalDetails: `SHA-256: ${sha256} • Format: ${detectedFormat}`,
    });
  }

  // 4. OVERALL ASSESSMENT
  let overallAssessment = '';
  if (isZeroByte) {
    overallAssessment =
      `EMPTY ARTIFACT (0 BYTES): File "${fileName}" contains zero bytes of data. ` +
      `No binary headers, executable code, printable strings, or byte entropy could be evaluated. ` +
      `If this artifact was acquired during an incident response triage, re-acquire the file from disk or network capture to ensure the payload was not truncated during transfer.`;
  } else if (formatMismatch && detectedFormat.includes('Executable')) {
    overallAssessment =
      `CRITICAL DECEPTION DETECTED: The file "${fileName}" is masquerading as a non-executable document, ` +
      `but its internal byte structure proves it is an executable program (${detectedFormat}). ` +
      `This is a classic technique used to deceive users into triggering code execution. Do not open or execute this file in an untrusted environment.`;
  } else if (findings.some((f) => f.severity === 'High')) {
    overallAssessment =
      `HIGH CAUTION ADVISED: Forensic examination of "${fileName}" identified significant indicators of concern, ` +
      `including suspicious API references or packing anomalies. While static analysis does not confirm runtime detonation, ` +
      `the presence of these capabilities warrants isolation and sandbox evaluation.`;
  } else if (findings.some((f) => f.severity === 'Medium')) {
    overallAssessment =
      `MODERATE RISK: Forensic evaluation identified configuration or entropy anomalies (such as high byte randomness or dangerous Android permissions) in "${fileName}". ` +
      `Review the individual findings below to determine whether these behaviors are legitimate for this application's intended purpose.`;
  } else {
    overallAssessment =
      `HEALTHY STATIC PROFILE: The file "${fileName}" matches its declared format (${detectedFormat}) and exhibits normal byte entropy (${entropy.toFixed(2)}/8.0). ` +
      `No deceptive headers, process injection signatures, or packing markers were detected during static inspection.`;
  }

  // 5. PRIORITIZED NEXT STEPS
  const prioritizedNextSteps: PrioritizedNextStep[] = [];
  if (isZeroByte) {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Verify artifact acquisition integrity and re-acquire file if truncated',
      rationale:
        'Determines whether the zero-byte file is a genuine system marker or the result of a failed forensic capture.',
    });
  } else if (formatMismatch || findings.some((f) => f.severity === 'Critical' || f.severity === 'High')) {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Quarantine the file and isolate the originating endpoint or inbox',
      rationale:
        'Prevents accidental execution or secondary propagation while the investigation is underway.',
    });
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Add SHA-256 hash to EDR and security gateway blocklists',
      rationale: `Cryptographic hash ${sha256.slice(0, 16)}... provides an immutable block marker across your environment.`,
    });
    prioritizedNextSteps.push({
      priority: 'High Priority',
      action: 'Query central SIEM / telemetry for any prior executions of this hash or file name',
      rationale:
        'Determines the blast radius: whether any host in your organization opened this file before analysis.',
    });
    prioritizedNextSteps.push({
      priority: 'Scheduled Hardening',
      action: 'Configure mail gateways to inspect binary magic bytes rather than trusting file extensions',
      rationale:
        'Permanently closes the vector where executable files disguised as PDFs or documents bypass perimeter filters.',
    });
  } else {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Verify code-signing certificate and vendor provenance if file is software',
      rationale: 'Ensures the binary originates from a verified, trusted publisher without tampering.',
    });
    prioritizedNextSteps.push({
      priority: 'High Priority',
      action: 'Attach hash and static forensic record to Case Workspace for documentation',
      rationale: 'Maintains an auditable chain of custody and forensic baseline.',
    });
    prioritizedNextSteps.push({
      priority: 'Scheduled Hardening',
      action: 'Conduct periodic review of endpoint application allowlisting policies',
      rationale: 'Guarantees that only authorized software runs across production workstations.',
    });
  }

  // 6. LIMITATIONS
  limitations.push(
    'Static binary analysis only: The file was not executed in a live virtual machine sandbox; dynamic runtime network traffic and memory behavior were not observed.'
  );
  limitations.push(
    'If the payload is protected with advanced anti-debugging or environmental keying, encrypted stages remain unopened until execution.'
  );

  if (unavailableChecks && unavailableChecks.length > 0) {
    unavailableChecks.forEach((chk) => {
      limitations.push(`${chk.name}: ${chk.reason} (${chk.defensiveAlternative})`);
    });
  }

  return {
    target: fileName,
    targetType: 'file',
    generatedAt: fileResult.timestamp || new Date().toISOString(),
    overallAssessment,
    whatWasDiscovered,
    whatIsWorkingWell,
    securityConcerns: findings.map((f) => {
      const confMeta = classifyFindingConfidence({
        title: f.title,
        category: f.category,
        observedResult: f.whatObserved,
        evidenceReference: f.technicalDetails,
      });
      return {
        ...f,
        verificationStatus: f.verificationStatus || confMeta.verificationStatus,
        confidenceLevel: f.confidenceLevel || confMeta.confidenceLevel,
        detectionMethod: f.detectionMethod || confMeta.detectionMethod,
        evidenceReference: f.evidenceReference || confMeta.evidenceReference,
        potentialFalsePositiveExplanation: f.potentialFalsePositiveExplanation || confMeta.potentialFalsePositiveExplanation,
        recommendedNextStep: f.recommendedNextStep || confMeta.recommendedNextStep,
      };
    }),
    prioritizedNextSteps,
    limitations,
    disclaimer: FILE_FORENSICS_DISCLAIMER,
    isAiGenerated: false,
    modelUsed: 'Veylith Deterministic DFIR File Engine',
  };
}
