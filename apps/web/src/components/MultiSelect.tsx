import { useEffect, useRef, useState } from "react";
import { Check, ChevronDown, X } from "lucide-react";

export interface MultiSelectOption {
  value: string;
  label: string;
}

interface MultiSelectProps {
  /** Short label shown when nothing is selected (e.g. "Severity") */
  label: string;
  options: MultiSelectOption[];
  /** Currently selected values */
  value: string[];
  onChange: (next: string[]) => void;
  /** Optional title attribute for accessibility */
  title?: string;
  /** Optional width class for the trigger button */
  widthClass?: string;
}

/**
 * Checkbox-style multi-select dropdown. Mirrors the look of the existing
 * `<select>` filter chips on FindingsPage. Selection is controlled by the
 * parent — no internal selection state — so URL-driven filters stay the
 * single source of truth.
 */
export default function MultiSelect({
  label,
  options,
  value,
  onChange,
  title,
  widthClass,
}: MultiSelectProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  // Close on outside click / Escape
  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const toggle = (v: string) => {
    if (value.includes(v)) onChange(value.filter((x) => x !== v));
    else onChange([...value, v]);
  };

  const clear = (e: React.MouseEvent) => {
    e.stopPropagation();
    onChange([]);
  };

  const count = value.length;
  const triggerText =
    count === 0
      ? `All ${label.toLowerCase()}`
      : count === 1
      ? (options.find((o) => o.value === value[0])?.label ?? value[0])
      : `${label} · ${count}`;

  return (
    <div ref={rootRef} className={`relative ${widthClass ?? ""}`} title={title}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={`flex items-center gap-2 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-500 ${
          count > 0
            ? "bg-indigo-900/40 border border-indigo-700/60 text-indigo-200"
            : "bg-gray-800 text-gray-300"
        }`}
      >
        <span className="truncate">{triggerText}</span>
        {count > 0 && (
          <span
            role="button"
            tabIndex={0}
            onClick={clear}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onChange([]);
              }
            }}
            className="rounded p-0.5 text-indigo-300 hover:bg-indigo-800/50 hover:text-white"
            title="Clear selection"
          >
            <X className="h-3 w-3" />
          </span>
        )}
        <ChevronDown className="h-3.5 w-3.5 opacity-70" />
      </button>

      {open && (
        <div className="absolute left-0 top-full z-30 mt-1 min-w-[12rem] rounded-md border border-gray-700 bg-gray-900 py-1 shadow-lg">
          {options.map((opt) => {
            const checked = value.includes(opt.value);
            return (
              <button
                type="button"
                key={opt.value}
                onClick={() => toggle(opt.value)}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm text-gray-200 hover:bg-gray-800"
              >
                <span
                  className={`flex h-4 w-4 items-center justify-center rounded border ${
                    checked
                      ? "border-indigo-500 bg-indigo-600"
                      : "border-gray-600 bg-gray-800"
                  }`}
                >
                  {checked && <Check className="h-3 w-3 text-white" />}
                </span>
                <span className="flex-1 truncate">{opt.label}</span>
              </button>
            );
          })}
          {count > 0 && (
            <div className="mt-1 border-t border-gray-800 px-2 pt-1">
              <button
                type="button"
                onClick={() => onChange([])}
                className="w-full rounded px-2 py-1 text-left text-xs text-gray-400 hover:bg-gray-800 hover:text-white"
              >
                Clear selection
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
