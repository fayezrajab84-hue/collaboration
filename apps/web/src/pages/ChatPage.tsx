import { useState, useRef, useEffect, useCallback } from "react";
import { Send, Sparkles, RotateCcw, ShieldAlert, User } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../lib/api";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Message {
  id:        string;
  role:      "user" | "assistant";
  content:   string;
  streaming: boolean;
}

interface OrgStats {
  totalOpen: number;
  critical:  number;
  high:      number;
  medium:    number;
  low:       number;
}

// ── Suggested questions ───────────────────────────────────────────────────────

const SUGGESTIONS = [
  "What are my most critical findings?",
  "Which repository has the most vulnerabilities?",
  "How do I fix SQL injection vulnerabilities?",
  "What is my overall security posture?",
  "Show me all unresolved container CVEs",
  "What secrets have been detected in my repos?",
  "What DAST findings were found on my domains?",
  "How should I prioritise my open findings?",
];

// ── Markdown renderer (lightweight) ──────────────────────────────────────────
// Converts **bold**, `code`, bullet lists, and numbered lists to JSX.

function renderMarkdown(text: string): React.ReactNode[] {
  const lines = text.split("\n");
  const elements: React.ReactNode[] = [];
  let key = 0;

  for (const line of lines) {
    if (!line.trim()) {
      elements.push(<div key={key++} className="h-2" />);
      continue;
    }

    // Bullet list
    if (/^[-*]\s/.test(line)) {
      elements.push(
        <div key={key++} className="flex gap-2 text-sm text-gray-300">
          <span className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-indigo-400" />
          <span>{inlineMarkdown(line.replace(/^[-*]\s/, ""))}</span>
        </div>
      );
      continue;
    }

    // Numbered list
    const numMatch = line.match(/^(\d+)\.\s(.+)/);
    if (numMatch) {
      elements.push(
        <div key={key++} className="flex gap-2 text-sm text-gray-300">
          <span className="flex-shrink-0 font-semibold text-indigo-400">{numMatch[1]}.</span>
          <span>{inlineMarkdown(numMatch[2])}</span>
        </div>
      );
      continue;
    }

    // Heading (##)
    if (/^##\s/.test(line)) {
      elements.push(
        <p key={key++} className="text-sm font-bold text-white mt-1">
          {line.replace(/^##\s/, "")}
        </p>
      );
      continue;
    }

    // Normal paragraph
    elements.push(
      <p key={key++} className="text-sm text-gray-300 leading-relaxed">
        {inlineMarkdown(line)}
      </p>
    );
  }

  return elements;
}

function inlineMarkdown(text: string): React.ReactNode {
  // Split on **bold** and `code`
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (/^\*\*(.+)\*\*$/.test(part)) {
      return <strong key={i} className="font-semibold text-white">{part.slice(2, -2)}</strong>;
    }
    if (/^`([^`]+)`$/.test(part)) {
      return <code key={i} className="rounded bg-gray-700 px-1 py-0.5 text-xs font-mono text-indigo-300">{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

// ── Message bubble ────────────────────────────────────────────────────────────

function MessageBubble({ message }: { message: Message }) {
  const isUser = message.role === "user";

  if (isUser) {
    return (
      <div className="flex justify-end">
        <div className="flex items-start gap-2.5 max-w-[80%]">
          <div className="rounded-2xl rounded-tr-sm bg-indigo-700 px-4 py-2.5">
            <p className="text-sm text-white">{message.content}</p>
          </div>
          <div className="flex-shrink-0 mt-0.5 flex h-7 w-7 items-center justify-center rounded-full bg-indigo-700">
            <User className="h-3.5 w-3.5 text-white" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex justify-start">
      <div className="flex items-start gap-2.5 max-w-[85%]">
        <div className="flex-shrink-0 mt-0.5 flex h-7 w-7 items-center justify-center rounded-full bg-indigo-950 border border-indigo-700">
          <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
        </div>
        <div className="rounded-2xl rounded-tl-sm border border-gray-800 bg-gray-900 px-4 py-3 space-y-1">
          {message.streaming && message.content === "" ? (
            <div className="flex gap-1 py-1">
              {[0, 1, 2].map((i) => (
                <span
                  key={i}
                  className="h-2 w-2 rounded-full bg-indigo-500 animate-bounce"
                  style={{ animationDelay: `${i * 150}ms` }}
                />
              ))}
            </div>
          ) : (
            <>
              {renderMarkdown(message.content)}
              {message.streaming && (
                <span className="inline-block h-4 w-0.5 bg-indigo-400 animate-pulse ml-0.5" />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Welcome screen ────────────────────────────────────────────────────────────

function WelcomeScreen({
  stats,
  onSuggest,
}: {
  stats: OrgStats | undefined;
  onSuggest: (q: string) => void;
}) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-6 py-12 text-center">
      {/* Icon */}
      <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-indigo-950 border border-indigo-700 shadow-xl shadow-indigo-950/50">
        <Sparkles className="h-7 w-7 text-indigo-400" />
      </div>

      <h2 className="text-2xl font-bold text-white">BreachLens AI</h2>
      <p className="mt-1.5 text-sm text-gray-400">
        Ask me anything about your security findings
      </p>

      {/* Stats pills */}
      {stats && stats.totalOpen > 0 && (
        <div className="mt-5 flex flex-wrap justify-center gap-2">
          <span className="rounded-full bg-gray-800 px-3 py-1 text-xs text-gray-300">
            {stats.totalOpen} open findings
          </span>
          {stats.critical > 0 && (
            <span className="rounded-full bg-red-900/40 border border-red-700/50 px-3 py-1 text-xs text-red-300">
              {stats.critical} critical
            </span>
          )}
          {stats.high > 0 && (
            <span className="rounded-full bg-orange-900/40 border border-orange-700/50 px-3 py-1 text-xs text-orange-300">
              {stats.high} high
            </span>
          )}
          {stats.medium > 0 && (
            <span className="rounded-full bg-amber-900/40 border border-amber-700/50 px-3 py-1 text-xs text-amber-300">
              {stats.medium} medium
            </span>
          )}
        </div>
      )}

      {/* Suggestions */}
      <div className="mt-8 w-full max-w-lg">
        <p className="mb-3 text-xs font-medium uppercase tracking-wider text-gray-500">
          Suggested questions
        </p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {SUGGESTIONS.slice(0, 6).map((q) => (
            <button
              key={q}
              onClick={() => onSuggest(q)}
              className="rounded-xl border border-gray-800 bg-gray-900 px-4 py-3 text-left text-sm text-gray-300 hover:border-indigo-700/60 hover:bg-indigo-950/30 hover:text-white transition-colors"
            >
              {q}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ChatPage() {
  const [messages, setMessages]   = useState<Message[]>([]);
  const [input,    setInput]      = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const bottomRef  = useRef<HTMLDivElement>(null);
  const inputRef   = useRef<HTMLTextAreaElement>(null);
  const abortRef   = useRef<AbortController | null>(null);

  const { data: stats } = useQuery<OrgStats>({
    queryKey: ["chat-stats"],
    queryFn:  () => apiClient.get<OrgStats>("/chat/stats").then((r) => r.data),
  });

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isLoading) return;

    setInput("");
    setIsLoading(true);

    // Add user message
    const userMsg: Message = {
      id:        crypto.randomUUID(),
      role:      "user",
      content:   trimmed,
      streaming: false,
    };

    // Add placeholder for AI response
    const aiId = crypto.randomUUID();
    const aiMsg: Message = { id: aiId, role: "assistant", content: "", streaming: true };

    setMessages((prev) => [...prev, userMsg, aiMsg]);

    // Build history for context (exclude the new placeholder)
    const history = messages
      .filter((m) => !m.streaming)
      .map(({ role, content }) => ({ role, content }));

    abortRef.current = new AbortController();

    try {
      const resp = await fetch("/api/chat", {
        method:      "POST",
        headers:     { "Content-Type": "application/json" },
        credentials: "include",
        body:        JSON.stringify({ message: trimmed, history }),
        signal:      abortRef.current.signal,
      });

      if (!resp.ok || !resp.body) {
        throw new Error(`HTTP ${resp.status}`);
      }

      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split("\n").filter((l) => l.startsWith("data: "));

        for (const line of lines) {
          try {
            const data = JSON.parse(line.slice(6)) as {
              token?: string;
              done?:  boolean;
              error?: string;
            };

            if (data.token) {
              setMessages((prev) =>
                prev.map((m) =>
                  m.id === aiId ? { ...m, content: m.content + data.token } : m
                )
              );
            }

            if (data.done || data.error) {
              setMessages((prev) =>
                prev.map((m) =>
                  m.id === aiId
                    ? {
                        ...m,
                        streaming: false,
                        content: data.error
                          ? `⚠️ ${data.error}`
                          : m.content,
                      }
                    : m
                )
              );
            }
          } catch {
            // malformed SSE line, skip
          }
        }
      }
    } catch (err) {
      if ((err as Error).name === "AbortError") return;
      setMessages((prev) =>
        prev.map((m) =>
          m.id === aiId
            ? { ...m, streaming: false, content: "⚠️ Connection failed. Is Ollama running?" }
            : m
        )
      );
    } finally {
      setIsLoading(false);
      abortRef.current = null;
      inputRef.current?.focus();
    }
  }, [isLoading, messages]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const handleReset = () => {
    abortRef.current?.abort();
    setMessages([]);
    setIsLoading(false);
    setInput("");
  };

  const hasMessages = messages.length > 0;

  return (
    <div className="flex h-full flex-col bg-gray-950">
      {/* ── Top bar ───────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
        <div className="flex items-center gap-3">
          <Sparkles className="h-5 w-5 text-indigo-400" />
          <h1 className="text-3xl font-bold text-white">AI Security Chat</h1>
        </div>
        {hasMessages && (
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            New chat
          </button>
        )}
      </div>

      {/* ── Messages area ─────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        {!hasMessages ? (
          <WelcomeScreen stats={stats} onSuggest={(q) => sendMessage(q)} />
        ) : (
          <div className="mx-auto max-w-3xl space-y-5 px-6 py-6">
            {messages.map((msg) => (
              <MessageBubble key={msg.id} message={msg} />
            ))}

            {/* More suggestions after conversation starts */}
            {!isLoading && messages.length >= 2 && messages.length % 4 === 0 && (
              <div className="flex flex-wrap gap-2 pt-2">
                {SUGGESTIONS.slice(0, 3).map((q) => (
                  <button
                    key={q}
                    onClick={() => sendMessage(q)}
                    className="rounded-full border border-gray-800 bg-gray-900 px-3 py-1.5 text-xs text-gray-400 hover:border-indigo-700/50 hover:text-indigo-300 transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            )}

            <div ref={bottomRef} />
          </div>
        )}
      </div>

      {/* ── Input bar ─────────────────────────────────────────────────────── */}
      <div className="border-t border-gray-800 bg-gray-900/80 px-6 py-4 backdrop-blur">
        <div className="mx-auto max-w-3xl">
          <div className="flex items-end gap-3 rounded-2xl border border-gray-700 bg-gray-800 px-4 py-3 focus-within:border-indigo-600 transition-colors">
            <ShieldAlert className="mb-0.5 h-4 w-4 flex-shrink-0 text-gray-500" />
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about your security findings… (Enter to send, Shift+Enter for newline)"
              rows={1}
              disabled={isLoading}
              className="flex-1 resize-none bg-transparent text-sm text-white placeholder-gray-500 focus:outline-none disabled:opacity-50"
              style={{ maxHeight: "120px", overflowY: "auto" }}
            />
            <button
              onClick={() => sendMessage(input)}
              disabled={isLoading || !input.trim()}
              className="flex-shrink-0 rounded-lg bg-indigo-700 p-1.5 text-white hover:bg-indigo-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <Send className="h-4 w-4" />
            </button>
          </div>
          <p className="mt-2 text-center text-[11px] text-gray-600">
            BreachLens AI uses your local findings as context · Powered by {" "}
            <span className="text-gray-500">llama3.2:3b</span> via Ollama
          </p>
        </div>
      </div>
    </div>
  );
}
