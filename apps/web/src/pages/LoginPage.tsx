/** BreachLens login page — matches the sidebar brand identity */

function BreachLensLoginLogo() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-full w-full"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="BreachLens logo"
    >
      <path
        d="M 4 3.5 H 20 V 12 C 20 18 16 21 12 22.8 C 8 21 4 18 4 12 Z"
        fill="#4f46e5"
        stroke="#a5b4fc"
        strokeWidth="0.9"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="11" r="4.2" fill="#ffffff" />
      <g stroke="#e0e7ff" strokeWidth="0.9" strokeLinecap="round">
        <line x1="12"    y1="5.3"   x2="12"    y2="6.6"  />
        <line x1="12"    y1="15.4"  x2="12"    y2="16.7" />
        <line x1="6.3"   y1="11"    x2="7.6"   y2="11"   />
        <line x1="16.4"  y1="11"    x2="17.7"  y2="11"   />
        <line x1="7.7"   y1="6.7"   x2="8.65"  y2="7.65" />
        <line x1="15.35" y1="14.35" x2="16.3"  y2="15.3" />
      </g>
      <path
        d="M 13.1 6.2 L 9.3 11.7 L 11.9 11.7 L 10.6 16.7 L 14.9 10.4 L 12.3 10.4 Z"
        fill="#ffffff"
        stroke="#4f46e5"
        strokeWidth="0.35"
        strokeLinejoin="round"
      />
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
