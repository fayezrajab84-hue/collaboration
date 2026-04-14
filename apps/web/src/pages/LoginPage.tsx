import { Shield } from "lucide-react";

export default function LoginPage() {
  const error = new URLSearchParams(window.location.search).get("error");

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-600 shadow-lg shadow-indigo-900">
            <Shield className="h-7 w-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">DevSecOps Platform</h1>
          <p className="text-sm text-gray-400">
            Centralized SAST, SCA, IaC, Secrets, DAST &amp; Pentest scanning
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
