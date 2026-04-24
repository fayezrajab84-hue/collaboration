import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { CheckCircle2, AlertCircle, Info, X } from "lucide-react";

/**
 * Lightweight toast system — no external dependencies.
 *
 * Usage
 * ─────
 *   const { toast } = useToast();
 *   toast.success("Scan queued");
 *   toast.error("Failed to save integration — check credentials");
 *   toast.info("Copied link to clipboard");
 *
 * Toasts auto-dismiss after 4s by default; pass `{ duration: 0 }` for
 * sticky toasts that the user has to close manually.
 */

type ToastKind = "success" | "error" | "info";

interface ToastItem {
  id:       number;
  kind:     ToastKind;
  message:  string;
  duration: number;
}

interface ToastOptions {
  duration?: number;
}

interface ToastAPI {
  success: (message: string, opts?: ToastOptions) => void;
  error:   (message: string, opts?: ToastOptions) => void;
  info:    (message: string, opts?: ToastOptions) => void;
}

interface ToastContextValue {
  toast: ToastAPI;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const DEFAULT_DURATION = 4000;

const KIND_STYLE: Record<ToastKind, { icon: typeof Info; cls: string }> = {
  success: { icon: CheckCircle2, cls: "border-indigo-700/60 bg-indigo-950/90 text-indigo-100" },
  error:   { icon: AlertCircle,  cls: "border-red-700/60    bg-red-950/90    text-red-100"     },
  info:    { icon: Info,         cls: "border-gray-700/60   bg-gray-900/95   text-gray-200"    },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id));
  }, []);

  const push = useCallback((kind: ToastKind, message: string, opts?: ToastOptions) => {
    const id = Date.now() + Math.random();
    const duration = opts?.duration ?? DEFAULT_DURATION;
    setToasts((ts) => [...ts, { id, kind, message, duration }]);
  }, []);

  const toast: ToastAPI = {
    success: (m, o) => push("success", m, o),
    error:   (m, o) => push("error",   m, o),
    info:    (m, o) => push("info",    m, o),
  };

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <ToastContainer toasts={toasts} dismiss={dismiss} />
    </ToastContext.Provider>
  );
}

function ToastContainer({
  toasts,
  dismiss,
}: {
  toasts:  ToastItem[];
  dismiss: (id: number) => void;
}) {
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
      {toasts.map((t) => (
        <Toast key={t.id} toast={t} onClose={() => dismiss(t.id)} />
      ))}
    </div>
  );
}

function Toast({ toast, onClose }: { toast: ToastItem; onClose: () => void }) {
  const { icon: Icon, cls } = KIND_STYLE[toast.kind];

  useEffect(() => {
    if (toast.duration === 0) return;   // sticky
    const timer = window.setTimeout(onClose, toast.duration);
    return () => window.clearTimeout(timer);
  }, [toast.duration, onClose]);

  return (
    <div
      role="status"
      className={`pointer-events-auto flex items-start gap-2 rounded-lg border px-4 py-2.5 text-sm shadow-xl backdrop-blur min-w-[260px] max-w-sm ${cls}`}
    >
      <Icon className="h-4 w-4 flex-shrink-0 mt-0.5" />
      <span className="flex-1 leading-snug">{toast.message}</span>
      <button
        onClick={onClose}
        className="flex-shrink-0 rounded p-0.5 text-current opacity-60 hover:opacity-100 transition-opacity"
        aria-label="Dismiss notification"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used inside <ToastProvider>");
  }
  return ctx;
}
