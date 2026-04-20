/** BreachLens login page — matches the sidebar brand identity */

function BreachLensLoginLogo() {
  return (
    <svg
      viewBox="0 0 36 36"
      className="h-full w-full"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="BreachLens logo"
    >
      <defs>
        <filter id="lp-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="1.4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <radialGradient id="lp-glass" cx="38%" cy="32%" r="70%">
          <stop offset="0%" stopColor="#818cf8" stopOpacity="0.28" />
          <stop offset="100%" stopColor="#3730a3" stopOpacity="0.07" />
        </radialGradient>
      </defs>

      {/* Outer lens body */}
      <circle cx="18" cy="18" r="15.5" stroke="#6366f1" strokeWidth="1.4" fill="url(#lp-glass)" />

      {/* Aperture ring */}
      <circle cx="18" cy="18" r="9.5" stroke="#4f46e5" strokeWidth="0.7" fill="none" opacity="0.55" />

      {/* 6 aperture blades */}
      <path d="M 27.36 19.65 A 9.5 9.5 0 0 1 24.11 25.28" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      <path d="M 21.25 26.93 A 9.5 9.5 0 0 1 14.75 26.93" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      <path d="M 11.89 25.28 A 9.5 9.5 0 0 1  8.64 19.65" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      <path d="M  8.64 16.35 A 9.5 9.5 0 0 1 11.89 10.72" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      <path d="M 14.75  9.07 A 9.5 9.5 0 0 1 21.25  9.07" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      <path d="M 24.11 10.72 A 9.5 9.5 0 0 1 27.36 16.35" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />

      {/* Scope crosshair */}
      <line x1="18" y1="3"    x2="18" y2="13.5" stroke="#6366f1" strokeWidth="1.1" strokeLinecap="round" opacity="0.8" />
      <line x1="18" y1="22.5" x2="18" y2="33"   stroke="#6366f1" strokeWidth="1.1" strokeLinecap="round" opacity="0.8" />
      <line x1="3"  y1="18"   x2="13.5" y2="18" stroke="#6366f1" strokeWidth="1.1" strokeLinecap="round" opacity="0.8" />
      <line x1="22.5" y1="18" x2="33"   y2="18" stroke="#6366f1" strokeWidth="1.1" strokeLinecap="round" opacity="0.8" />

      {/* Central focal point */}
      <g filter="url(#lp-glow)">
        <circle cx="18" cy="18" r="3.6" fill="#3730a3" stroke="#6366f1" strokeWidth="0.8" />
        <circle cx="18" cy="18" r="1.9" fill="#6366f1" />
      </g>
      {/* Lens glint */}
      <circle cx="19.2" cy="16.8" r="0.75" fill="#c7d2fe" opacity="0.72" />
    </svg>
  );
}

export default function LoginPage() {
  const error = new URLSearchParams(window.location.search).get("error");

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 px-4">
      <div className="w-full max-w-sm">

        {/* Brand */}
        <div className="mb-8 flex flex-col items-center gap-4 text-center">
          <div className="flex h-20 w-20 items-center justify-center rounded-2xl bg-indigo-950 ring-1 ring-indigo-700 shadow-xl shadow-indigo-950">
            <BreachLensLoginLogo />
          </div>
          <div>
            <h1 className="text-3xl font-extrabold tracking-wide text-white">BreachLens</h1>
            <p className="mt-0.5 text-xs font-semibold tracking-widest text-indigo-400 uppercase">
              DevSecOps Platform
            </p>
          </div>
          <p className="text-sm text-gray-400">
            Unified SAST · SCA · IaC · Secrets · DAST · Pentest
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="mb-4 rounded-lg border border-red-800 bg-red-900/40 px-4 py-3 text-sm text-red-300">
            Authentication failed. Please try again.
          </div>
        )}

        {/* Login card */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-8">
          <h2 className="mb-6 text-center text-base font-semibold text-white">Sign in to continue</h2>

          <a
            href="/auth/github"
            className="flex w-full items-center justify-center gap-3 rounded-lg bg-white px-4 py-3 text-sm font-semibold text-gray-900 transition hover:bg-gray-100"
          >
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
            Continue with GitHub
          </a>

          <p className="mt-4 text-center text-xs text-gray-500">
            Your repositories and scan results are stored only in your self-hosted instance.
          </p>
        </div>
      </div>
    </div>
  );
}
