import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/utils";

/**
 * Canonical button component.
 *
 * Variants
 * ────────
 * • primary   — filled indigo, the default "do this" action
 * • secondary — outlined/ghost, for less-emphasised actions
 * • danger    — destructive (delete, remove, cancel scan)
 * • ghost     — borderless, icon-forward (row actions, toolbars)
 *
 * Sizes
 * ─────
 * • sm — compact, for dense toolbars and inline chips  (px-3 py-1.5 text-xs)
 * • md — default standard action                       (px-4 py-2   text-sm)
 * • lg — primary page-level CTA (Login, Generate, Scan)(px-5 py-2.5 text-sm)
 *
 * Inline one-offs can still use `className` on top for specialised layouts
 * (e.g. `w-full` on modal submit buttons).
 */

type Variant = "primary" | "secondary" | "danger" | "ghost";
type Size    = "sm" | "md" | "lg";

const VARIANT_CLASSES: Record<Variant, string> = {
  primary:
    "bg-indigo-600 text-white hover:bg-indigo-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 disabled:opacity-50 disabled:hover:bg-indigo-600",
  secondary:
    "border border-gray-700 bg-gray-800 text-gray-300 hover:border-gray-600 hover:bg-gray-700 hover:text-gray-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 disabled:opacity-50",
  danger:
    "border border-red-800 bg-red-950/30 text-red-400 hover:border-red-700 hover:bg-red-900/40 hover:text-red-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-50",
  ghost:
    "text-gray-400 hover:bg-gray-800 hover:text-gray-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 disabled:opacity-50",
};

const SIZE_CLASSES: Record<Size, string> = {
  sm: "px-3 py-1.5 text-xs",
  md: "px-4 py-2   text-sm",
  lg: "px-5 py-2.5 text-sm",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?:    Size;
  leftIcon?:  ReactNode;
  rightIcon?: ReactNode;
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "primary", size = "md", leftIcon, rightIcon, className, children, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors",
        VARIANT_CLASSES[variant],
        SIZE_CLASSES[size],
        className,
      )}
      {...rest}
    >
      {leftIcon}
      {children}
      {rightIcon}
    </button>
  );
});

export default Button;
