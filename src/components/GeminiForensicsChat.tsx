import React, { useState, useRef, useEffect } from 'react';
import { CaseRecord, ChatMessage } from '../types';
import {
  Sparkles,
  Send,
  User,
  Bot,
  BrainCircuit,
  ShieldCheck,
  Zap,
  Cpu,
  Trash2,
  Copy,
  Check,
  Info,
  Clock,
  Layers,
  Terminal,
} from 'lucide-react';

interface GeminiForensicsChatProps {
  currentCase?: CaseRecord;
  investigationContext?: any;
  isCompact?: boolean;
}

type ForensicsRole = 'lead_investigator' | 'threat_intel' | 'reverse_engineer';
type ModelChoice = 'gemini-3.8-flash' | 'gemini-3.1-flash-lite' | 'gemini-4-argon';

export const GeminiForensicsChat: React.FC<GeminiForensicsChatProps> = ({
  currentCase,
  investigationContext,
  isCompact = false,
}) => {
  const [role, setRole] = useState<ForensicsRole>('threat_intel');
  const [modelPreference, setModelPreference] = useState<ModelChoice>('gemini-3.8-flash');
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const targetLabel = investigationContext?.domain || currentCase?.id || 'Active Investigation';

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'init-1',
      role: 'model',
      content: `Greetings Analyst. I am Veylith AI Copilot, specialized for digital forensics, infrastructure hardening, and defensible incident correlation.

Currently active context: **${targetLabel}** (${currentCase?.evidence?.length || 0} evidence artifacts tracked).
Ask any question regarding web server hardening (Nginx / Apache / Express), curl verification commands, Shannon entropy, Android APKs, or network telemetry anomalies.`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      modelUsed: 'gemini-3.8-flash',
      roleName: 'Threat Intel & Infrastructure Analyst',
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const roleMeta: Record<
    ForensicsRole,
    { title: string; subtitle: string; icon: React.ReactNode; defaultModel: ModelChoice; badgeColor: string }
  > = {
    threat_intel: {
      title: 'Threat Intel & Hardening Analyst',
      subtitle: 'Nginx/Apache remediation, curl checks & CISA KEV',
      icon: <ShieldCheck className="w-4 h-4 text-blue-500" />,
      defaultModel: 'gemini-3.8-flash',
      badgeColor: 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 border-blue-300 dark:border-blue-800',
    },
    lead_investigator: {
      title: 'Lead DFIR Investigator',
      subtitle: 'Complex reasoning, attack trees & court defensibility',
      icon: <BrainCircuit className="w-4 h-4 text-purple-500" />,
      defaultModel: 'gemini-3.8-flash',
      badgeColor: 'bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border-purple-300 dark:border-purple-800',
    },
    reverse_engineer: {
      title: 'Static Binary Specialist',
      subtitle: 'Fast triage, entropy, magic bytes & APK inspection',
      icon: <Zap className="w-4 h-4 text-teal-500" />,
      defaultModel: 'gemini-3.1-flash-lite',
      badgeColor: 'bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300 border-teal-300 dark:border-teal-800',
    },
  };

  const handleRoleChange = (newRole: ForensicsRole) => {
    setRole(newRole);
    setModelPreference(roleMeta[newRole].defaultModel);
  };

  const quickPrompts = React.useMemo(() => {
    if (investigationContext?.domain) {
      const d = investigationContext.domain;
      return [
        `How do I fix missing security headers in Nginx for ${d}?`,
        `Generate curl commands to verify domain security for ${d}`,
        `Explain real-world attack scenarios for ${d} without headers`,
        `Why are missing HTTP headers classified as Low severity?`,
      ];
    }

    if (!currentCase || currentCase.evidence.length === 0) {
      return [
        'How do I fix missing security headers in Nginx?',
        'Generate curl commands to verify domain security and headers',
        'Explain educational attack scenarios for missing CSP & X-Frame-Options',
        'Explain Shannon entropy (>7.2) vs benign file compression',
        'How to detect DNS tunneling and C2 beacons in PCAP?',
      ];
    }

    const prompts: string[] = [
      'How do I fix missing security headers in Nginx?',
      'Generate curl commands to verify domain security',
    ];
    const files = currentCase.evidence.filter((e) => e.type === 'file' || e.type === 'hash');
    const netEntities = currentCase.evidence.filter((e) => e.type === 'ip' || e.type === 'domain');
    const cves = currentCase.evidence.filter((e) => e.type === 'cve');

    if (files.length > 0) {
      prompts.push(`Analyze the entropy and binary structure of artifact ${files[0].name}.`);
    }
    if (netEntities.length > 0) {
      prompts.push(`Correlate observed network telemetry for ${netEntities[0].value} against known threat infrastructure.`);
    }
    if (cves.length > 0) {
      prompts.push(`Assess exploitability and recommended defensive controls for ${cves[0].name}.`);
    }

    if (prompts.length < 4) {
      prompts.push(`Review findings in case ${currentCase.id} and identify unresolved investigation gaps.`);
    }

    return prompts.slice(0, 5);
  }, [currentCase, investigationContext]);

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || loading) return;

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const newHistory = [...messages, userMsg];
    setMessages(newHistory);
    setInputMessage('');
    setLoading(true);

    try {
      const res = await fetch('/api/gemini/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: newHistory.map((m) => ({ role: m.role, content: m.content })),
          roleId: role,
          modelPreference,
          activeCase: currentCase
            ? {
                id: currentCase.id,
                title: currentCase.title,
                scope: currentCase.scope,
                evidence: currentCase.evidence,
                findings: currentCase.findings,
              }
            : undefined,
          investigationContext,
        }),
      });

      const data = await res.json();
      if (data.reply) {
        const modelMsg: ChatMessage = {
          id: `mod-${Date.now()}`,
          role: 'model',
          content: data.reply,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          modelUsed: data.modelUsed || modelPreference,
          roleName: roleMeta[role].title,
          isFallback: data.isFallback,
        };
        setMessages((prev) => [...prev, modelMsg]);
      } else {
        const errorMsg: ChatMessage = {
          id: `err-${Date.now()}`,
          role: 'model',
          content: `⚠️ API Advisory: ${data.error || 'Unable to retrieve model response.'} Non-AI deterministic checks remain operational.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          modelUsed: 'Veylith Core Fallback',
        };
        setMessages((prev) => [...prev, errorMsg]);
      }
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        role: 'model',
        content: `⚠️ Connection Error: ${err.message}. Please check local network connectivity.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const renderMessageContent = (content: string, isUser: boolean, messageId: string) => {
    if (isUser || !content.includes('```')) {
      return (
        <div className={`leading-relaxed whitespace-pre-wrap font-sans text-xs ${isUser ? 'text-white' : 'text-slate-800 dark:text-slate-200'}`}>
          {content}
        </div>
      );
    }

    const parts = content.split(/(```[\s\S]*?```)/g);
    return (
      <div className="leading-relaxed space-y-2 text-xs text-slate-800 dark:text-slate-200">
        {parts.map((part, pIdx) => {
          if (part.startsWith('```') && part.endsWith('```')) {
            const firstLineBreak = part.indexOf('\n');
            const lang = firstLineBreak !== -1 ? part.slice(3, firstLineBreak).trim() : '';
            const code = firstLineBreak !== -1 ? part.slice(firstLineBreak + 1, -3) : part.slice(3, -3);
            const snippetKey = `${messageId}-code-${pIdx}`;

            return (
              <div key={pIdx} className="my-2 rounded-xl bg-slate-900 border border-slate-800 overflow-hidden text-[11px] font-mono">
                <div className="flex items-center justify-between px-3 py-1.5 bg-slate-950/80 border-b border-slate-800/80 text-slate-400 text-[10px]">
                  <span className="font-semibold uppercase tracking-wider">{lang || 'DIRECTIVE / CODE'}</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(code, snippetKey)}
                    className="flex items-center gap-1 hover:text-white transition px-1.5 py-0.5 rounded hover:bg-slate-800"
                  >
                    {copiedId === snippetKey ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy Code</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-3 text-emerald-400 overflow-x-auto leading-relaxed">
                  <code>{code}</code>
                </pre>
              </div>
            );
          }

          return (
            <div key={pIdx} className="whitespace-pre-wrap font-sans">
              {part}
            </div>
          );
        })}
      </div>
    );
  };

  const handleClearHistory = () => {
    if (confirm('Clear chat history for this investigation session?')) {
      setMessages([
        {
          id: 'init-fresh',
          role: 'model',
          content: `Session reset. Ready for analysis under role **${roleMeta[role].title}** using model **${modelPreference}**.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          modelUsed: modelPreference,
          roleName: roleMeta[role].title,
        },
      ]);
    }
  };

  return (
    <div className={`bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 flex flex-col shadow-xs ${isCompact ? 'h-[500px]' : 'h-[650px]'}`}>
      {/* Top Chat Header & Role Selector */}
      <div className="p-3.5 border-b border-slate-200/80 dark:border-slate-800 space-y-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-purple-50 dark:bg-purple-950/80 border border-purple-200 dark:border-purple-800 text-purple-600 dark:text-purple-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs md:text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                Gemini Forensics Multi-Turn Copilot
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${roleMeta[role].badgeColor}`}>
                  {modelPreference}
                </span>
              </h3>
              <p className="text-[11px] text-slate-400">
                Grounding in case <span className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{currentCase?.id || 'Active Workspace'}</span> ({currentCase?.evidence.length || 0} evidence items)
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1.5 self-end sm:self-auto text-xs">
            {/* Model Selection Override */}
            <div className="flex items-center bg-slate-100 dark:bg-slate-800 rounded-lg p-0.5 border border-slate-200 dark:border-slate-700">
              <button
                onClick={() => setModelPreference('gemini-4-argon')}
                title="Complex tasks: Deep reasoning & thinking"
                className={`px-2 py-1 rounded text-[10px] font-mono font-semibold transition ${
                  modelPreference === 'gemini-4-argon'
                    ? 'bg-purple-600 text-white shadow-xs'
                    : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                4-argon (Complex)
              </button>
              <button
                onClick={() => setModelPreference('gemini-3.8-flash')}
                title="General tasks: Balanced correlation & speed"
                className={`px-2 py-1 rounded text-[10px] font-mono font-semibold transition ${
                  modelPreference === 'gemini-3.8-flash'
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                3.8-flash (General)
              </button>
              <button
                onClick={() => setModelPreference('gemini-3.1-flash-lite')}
                title="Fast tasks: Rapid string & opcode triage"
                className={`px-2 py-1 rounded text-[10px] font-mono font-semibold transition ${
                  modelPreference === 'gemini-3.1-flash-lite'
                    ? 'bg-teal-600 text-white shadow-xs'
                    : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                3.1-lite (Fast)
              </button>
            </div>

            <button
              onClick={handleClearHistory}
              title="Clear Conversation"
              className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Specialized Persona Roles */}
        <div className="grid grid-cols-3 gap-1.5 pt-1">
          {(['lead_investigator', 'threat_intel', 'reverse_engineer'] as ForensicsRole[]).map((rKey) => {
            const meta = roleMeta[rKey];
            const active = role === rKey;
            return (
              <button
                key={rKey}
                onClick={() => handleRoleChange(rKey)}
                className={`px-2.5 py-1.5 rounded-xl border text-left transition flex items-center gap-2 ${
                  active
                    ? 'bg-slate-50 dark:bg-slate-800/90 border-teal-500/80 shadow-2xs'
                    : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50/50 dark:hover:bg-slate-800/40 text-slate-500'
                }`}
              >
                <div className="shrink-0">{meta.icon}</div>
                <div className="min-w-0">
                  <p className={`text-[11px] font-bold truncate ${active ? 'text-slate-900 dark:text-white' : 'text-slate-600 dark:text-slate-400'}`}>
                    {meta.title}
                  </p>
                  <p className="text-[9px] text-slate-400 truncate hidden md:block">
                    {meta.subtitle}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Messages Scroll Thread */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {messages.map((m) => {
          const isUser = m.role === 'user';
          return (
            <div key={m.id} className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'}`}>
              {!isUser && (
                <div className="w-7 h-7 rounded-xl bg-purple-50 dark:bg-purple-950 border border-purple-200 dark:border-purple-800 flex items-center justify-center text-purple-600 dark:text-purple-400 shrink-0 mt-0.5 shadow-2xs">
                  <Bot className="w-4 h-4" />
                </div>
              )}

              <div className={`max-w-[85%] rounded-2xl p-3.5 space-y-2 shadow-2xs ${
                isUser
                  ? 'bg-teal-600 text-white rounded-tr-xs'
                  : 'bg-slate-50 dark:bg-slate-800/70 border border-slate-200/80 dark:border-slate-700/80 text-slate-800 dark:text-slate-100 rounded-tl-xs'
              }`}>
                {!isUser && (
                  <div className="flex items-center justify-between gap-2 pb-1 border-b border-slate-200/60 dark:border-slate-700/60 text-[10px]">
                    <div className="flex items-center gap-1.5 font-semibold text-slate-600 dark:text-slate-300">
                      <span>{m.roleName || 'Veylith AI'}</span>
                      {m.modelUsed && (
                        <span className="font-mono text-[9px] px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
                          {m.modelUsed}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1 text-slate-400">
                      <span>{m.timestamp}</span>
                      <button
                        onClick={() => copyToClipboard(m.content, m.id)}
                        className="p-1 hover:text-slate-600 dark:hover:text-slate-200 transition"
                        title="Copy message"
                      >
                        {copiedId === m.id ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>
                )}

                {/* Message Body with Markdown and Code Container styling */}
                {renderMessageContent(m.content, isUser, m.id)}

                {isUser && (
                  <div className="text-right text-[10px] text-teal-200">
                    {m.timestamp}
                  </div>
                )}
              </div>

              {isUser && (
                <div className="w-7 h-7 rounded-xl bg-teal-700 text-white flex items-center justify-center shrink-0 mt-0.5 shadow-2xs">
                  <User className="w-4 h-4" />
                </div>
              )}
            </div>
          );
        })}

        {loading && (
          <div className="flex gap-3 justify-start items-center text-xs text-slate-400 animate-pulse">
            <div className="w-7 h-7 rounded-xl bg-purple-50 dark:bg-purple-950 border border-purple-200 dark:border-purple-800 flex items-center justify-center text-purple-600 shrink-0">
              <Bot className="w-4 h-4" />
            </div>
            <div className="p-3 bg-slate-50 dark:bg-slate-800/70 border border-slate-200/80 dark:border-slate-700/80 rounded-2xl rounded-tl-xs flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-purple-500 animate-bounce" />
              <div className="w-2 h-2 rounded-full bg-purple-500 animate-bounce delay-150" />
              <div className="w-2 h-2 rounded-full bg-purple-500 animate-bounce delay-300" />
              <span className="font-mono text-[11px] ml-1">Reasoning with {modelPreference}...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Quick Prompt Chips */}
      <div className="px-3 py-1.5 border-t border-slate-100 dark:border-slate-800 flex gap-1.5 overflow-x-auto text-[11px] scrollbar-none select-none">
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => handleSendMessage(p)}
            disabled={loading}
            className="shrink-0 px-2.5 py-1 rounded-lg bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 border border-slate-200/70 dark:border-slate-700/70 transition truncate max-w-[280px]"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Message Input Bar */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        className="p-3 border-t border-slate-200/80 dark:border-slate-800 flex items-center gap-2"
      >
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          placeholder={`Ask ${roleMeta[role].title} using ${modelPreference}...`}
          className="flex-1 px-3.5 py-2 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white placeholder:text-slate-400 outline-none focus:ring-2 focus:ring-teal-500/20 focus:border-teal-500"
        />
        <button
          type="submit"
          disabled={!inputMessage.trim() || loading}
          className="px-4 py-2 bg-teal-600 hover:bg-teal-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition shadow-xs flex items-center gap-1.5"
        >
          <Send className="w-3.5 h-3.5" />
          <span>Send</span>
        </button>
      </form>
    </div>
  );
};
