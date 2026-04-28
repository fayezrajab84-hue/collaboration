interface Props {
  /** "lg" for drawer header, "sm" for table row (icon-only with title tooltip). */
  size?: "lg" | "sm";
}

/**
 * Crosshair-on-target glyph — readable at 12-16px, conveys "live attack
 * being observed" without depending on text. Hand-drawn (not Lucide's
 * Target) so the inner ring stays visible at small sizes; Lucide's
 * Target loses the dot at h-3.
 */
function ActiveAttackMark({ className = "" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      {/* Outer ring */}
      <circle cx="12" cy="12" r="9" />
      {/* Inner ring */}
      <circle cx="12" cy="12" r="5" />
      {/* Bullseye dot */}
      <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
      {/* Crosshair lines — break for the rings so the icon doesn't read
          as a solid mass at small sizes. */}
      <line x1="12" y1="1.5"  x2="12" y2="5" />
      <line x1="12" y1="19"   x2="12" y2="22.5" />
      <line x1="1.5"  y1="12" x2="5" y2="12" />
      <line x1="19"   y1="12" x2="22.5" y2="12" />
    </svg>
  );
}

/**
 * Visual marker for RUNTIME findings where the IDS observed offensive
 * activity (rule.groups contains attack/exploit OR MITRE tactic falls
 * in the offensive set).
 *
 * Visual tier: WARNING. Faded rose border + subtle wash, no solid fill.
 * Pairs with ExploitSuccessBadge (CRITICAL tier — solid red fill) so
 * the operator can scan a row and instantly read "attack attempted"
 * vs "attack succeeded" by colour weight, not just text.
 *
 *   (legacy ProofOfExploitBadge was removed — its meaning is
 *                           (CRITICAL tier — solid red, shield+bolt)
 *   ActiveAttackBadge    → attack attempted (this badge)
 *                           (WARNING tier — faded rose, crosshair)
 *   ExploitSuccessBadge  → attack landed (success signals present)
 *                           (CRITICAL tier — solid red, shield-off)
 *
 * Render gating is the caller's responsibility — pair with
 * hasActiveAttack() from lib/findings so the predicate stays in one
 * place.
 */
// Sibling pill metrics: both ActiveAttackBadge and ExploitSuccessBadge
// share the same dimensions (text-[10px] uppercase tracking-wide,
// px-2 py-0.5, h-3 w-3 icon) so when they render side-by-side in the
// confidence cell they read as paired siblings rather than mismatched
// pills.
//
// Colour: matches the CONFIRMED confidence chip (bg-gray-800/60 +
// text-red-300/90 + border-gray-700/50) so all "investigate" red-text
// signals on a row use one palette. ExploitSuccessBadge keeps the
// stronger red border to escalate visual weight when the attack
// landed; this badge stays on the gray-bordered tier for "attempted".
const PILL = "border-gray-700/50 bg-gray-800/60 text-red-300/90";

export default function ActiveAttackBadge({ size = "lg" }: Props) {
  if (size === "sm") {
    // Pill with abbreviated text — sits inline with the Confidence chip
    // and the (mutually exclusive) Exploit pill at matching height.
    return (
      <span
        title="Active Attack — Wazuh observed offensive activity matching this rule on the live workload (attempt, not necessarily landed)"
        className={`inline-flex items-center gap-0.5 rounded-full border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide ${PILL}`}
        aria-label="Active Attack"
      >
        <ActiveAttackMark className="h-2.5 w-2.5" />
        Attack
      </span>
    );
  }
  return (
    <span
      title="Wazuh observed offensive activity on the live workload — this rule's groups or MITRE tactic indicate an active attack pattern, not a passive observation."
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${PILL}`}
    >
      <ActiveAttackMark className="h-3 w-3" />
      Active Attack
    </span>
  );
}
