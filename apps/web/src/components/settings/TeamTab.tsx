/**
 * Team tab — manage org members + pending invitations.
 *
 * Read access for any member of the org. Write actions (role change,
 * remove, invite, revoke) require ADMIN+ — gated server-side; UI hides
 * the controls via <Can role="ADMIN">.
 *
 * Last-OWNER protection lives on the server — this UI surfaces the
 * resulting 409 errors via toast.
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Users, UserPlus, Trash2, Mail, Loader2, AlertCircle, X, Info } from "lucide-react";
import { membersApi, type MemberRole, type Member, type Invitation } from "../../lib/api";
import { useRole } from "../../hooks/useRole";
import { useToast } from "../../hooks/useToast";
import Can from "../Can";
import { formatDate } from "../../lib/utils";

const ROLES: MemberRole[] = ["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "VIEWER"];

const ROLE_DESC: Record<MemberRole, string> = {
  OWNER:     "Full control, including billing and org deletion",
  ADMIN:     "Manage members, integrations, providers, policies",
  SECURITY:  "Triage findings, create tickets, manage suppressions",
  DEVELOPER: "View findings, run scans, comment",
  VIEWER:    "Read-only access to scans and findings",
};

export default function TeamTab() {
  const qc      = useQueryClient();
  const { toast } = useToast();
  const role    = useRole();
  const isAdmin = role.can("ADMIN");

  const { data: members = [] } = useQuery({
    queryKey: ["members"],
    queryFn:  membersApi.list,
  });

  // Pending invitations only visible to ADMIN+ (API returns 403 otherwise)
  const { data: invitations = [] } = useQuery({
    queryKey: ["members", "invitations"],
    queryFn:  membersApi.listInvitations,
    enabled:  isAdmin,
  });

  return (
    <div className="space-y-6">
      <header className="flex items-center gap-2">
        <Users className="h-4 w-4 text-indigo-400" />
        <h2 className="text-base font-semibold text-white">Team</h2>
        <span className="ml-auto text-xs text-gray-500">
          {members.length} member{members.length === 1 ? "" : "s"}
          {isAdmin && invitations.length > 0 && ` · ${invitations.length} pending`}
        </span>
      </header>

      <MembersTable members={members} qc={qc} toast={toast} isAdmin={isAdmin} />

      <Can role="ADMIN">
        <InviteForm qc={qc} toast={toast} />
        {invitations.length > 0 && (
          <InvitationsTable invitations={invitations} qc={qc} toast={toast} />
        )}
      </Can>
    </div>
  );
}

// ── Members table ────────────────────────────────────────────────────────────

function MembersTable({
  members, qc, toast, isAdmin,
}: {
  members:  Member[];
  qc:       ReturnType<typeof useQueryClient>;
  toast:    ReturnType<typeof useToast>["toast"];
  isAdmin:  boolean;
}) {
  const changeRole = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: MemberRole }) =>
      membersApi.changeRole(userId, role),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["members"] });
      toast.success("Role updated");
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      toast.error(err.response?.data?.error ?? err.message);
    },
  });

  const remove = useMutation({
    mutationFn: (userId: string) => membersApi.remove(userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["members"] });
      toast.success("Member removed");
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      toast.error(err.response?.data?.error ?? err.message);
    },
  });

  return (
    <div className="overflow-hidden rounded-lg border border-gray-800">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-gray-800 bg-gray-900/60 text-gray-400">
            <th className="px-3 py-2 font-semibold">Member</th>
            <th className="px-3 py-2 font-semibold">Role</th>
            <th className="px-3 py-2 font-semibold">Joined</th>
            {isAdmin && <th className="px-3 py-2 font-semibold w-10" />}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/60">
          {members.map((m) => (
            <tr key={m.userId} className="hover:bg-gray-800/30">
              <td className="px-3 py-2">
                <div className="flex items-center gap-2">
                  {m.avatarUrl && (
                    <img src={m.avatarUrl} alt="" className="h-6 w-6 rounded-full ring-1 ring-gray-700" />
                  )}
                  <div className="min-w-0">
                    <div className="font-medium text-gray-200">
                      {m.username}
                      {m.isYou && (
                        <span className="ml-2 rounded bg-indigo-900/40 px-1.5 py-0.5 text-[10px] text-indigo-300 ring-1 ring-indigo-800/50">
                          you
                        </span>
                      )}
                    </div>
                    {m.email && <div className="text-[10px] text-gray-500">{m.email}</div>}
                  </div>
                </div>
              </td>
              <td className="px-3 py-2">
                {isAdmin ? (
                  <select
                    value={m.role}
                    title={ROLE_DESC[m.role]}
                    disabled={changeRole.isPending}
                    onChange={(e) => {
                      const newRole = e.target.value as MemberRole;
                      if (newRole !== m.role) changeRole.mutate({ userId: m.userId, role: newRole });
                    }}
                    className="rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs text-gray-200 hover:border-gray-700 focus:border-indigo-700 focus:outline-none"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>{r}</option>
                    ))}
                  </select>
                ) : (
                  <span className="rounded bg-gray-800/60 px-2 py-0.5 font-mono text-[10px] text-gray-300">
                    {m.role}
                  </span>
                )}
              </td>
              <td className="px-3 py-2 text-[11px] text-gray-500 whitespace-nowrap">
                {formatDate(m.joinedAt)}
              </td>
              {isAdmin && (
                <td className="px-3 py-2 text-right">
                  {!m.isYou && (
                    <button
                      onClick={() => {
                        if (confirm(`Remove ${m.username} from the org?`)) {
                          remove.mutate(m.userId);
                        }
                      }}
                      disabled={remove.isPending}
                      className="rounded p-1 text-gray-500 hover:bg-red-950/40 hover:text-red-300 disabled:opacity-40"
                      title="Remove member"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Invite form ──────────────────────────────────────────────────────────────

function InviteForm({
  qc, toast,
}: {
  qc:    ReturnType<typeof useQueryClient>;
  toast: ReturnType<typeof useToast>["toast"];
}) {
  const [username, setUsername] = useState("");
  const [role, setRole]         = useState<MemberRole>("DEVELOPER");

  const create = useMutation({
    mutationFn: () => membersApi.createInvitation({ githubUsername: username.trim(), role }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["members", "invitations"] });
      toast.success(`Invitation sent to ${username}`);
      setUsername("");
      setRole("DEVELOPER");
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      toast.error(err.response?.data?.error ?? err.message);
    },
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim()) return;
    create.mutate();
  }

  // The invited user reaches the OAuth flow at the same origin the operator
  // is currently on. window.location.origin works for both localhost dev and
  // any deployed instance — no env-var needed.
  const loginUrl = typeof window !== "undefined" ? window.location.origin : "";

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-lg border border-gray-800 bg-gray-900/40 p-3"
    >
      <div className="mb-2 flex items-center gap-2">
        <UserPlus className="h-3.5 w-3.5 text-indigo-400" />
        <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
          Invite by GitHub username
        </span>
      </div>
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex-1 min-w-[200px]">
          <span className="mb-1 block text-[10px] font-semibold uppercase tracking-wider text-gray-500">
            Username
          </span>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="octocat"
            disabled={create.isPending}
            className="w-full rounded border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-indigo-700 focus:outline-none"
          />
        </label>
        <label>
          <span className="mb-1 block text-[10px] font-semibold uppercase tracking-wider text-gray-500">
            Role
          </span>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as MemberRole)}
            disabled={create.isPending}
            className="rounded border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 focus:border-indigo-700 focus:outline-none"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </label>
        <button
          type="submit"
          disabled={!username.trim() || create.isPending}
          className="inline-flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {create.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <UserPlus className="h-3 w-3" />}
          Create invitation
        </button>
      </div>
      {/* Out-of-band notification banner — BreachLens has no email infra today.
          Keep this until Phase 22 PR 3 (SSO) lands, at which point email can
          be captured at IdP-config time and a real notification sent. */}
      <div className="mt-3 flex items-start gap-2 rounded-md border border-indigo-900/40 bg-indigo-950/30 px-3 py-2 text-[11px] text-gray-300">
        <Info className="h-3.5 w-3.5 mt-0.5 shrink-0 text-indigo-400" />
        <div className="leading-relaxed">
          <strong className="text-gray-100">No email is sent.</strong>{" "}
          Tell the invited user to sign in at{" "}
          <code className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-indigo-300">
            {loginUrl}
          </code>{" "}
          with their GitHub account — they'll be added to the org automatically on next sign-in.
          Username match is case-insensitive.
        </div>
      </div>
    </form>
  );
}

// ── Pending invitations table ────────────────────────────────────────────────

function InvitationsTable({
  invitations, qc, toast,
}: {
  invitations: Invitation[];
  qc:          ReturnType<typeof useQueryClient>;
  toast:       ReturnType<typeof useToast>["toast"];
}) {
  const revoke = useMutation({
    mutationFn: (id: string) => membersApi.revokeInvitation(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["members", "invitations"] });
      toast.success("Invitation revoked");
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      toast.error(err.response?.data?.error ?? err.message);
    },
  });

  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <Mail className="h-3.5 w-3.5 text-indigo-400" />
        <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
          Pending invitations
        </span>
      </div>
      <div className="overflow-hidden rounded-lg border border-gray-800">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-gray-800 bg-gray-900/60 text-gray-400">
              <th className="px-3 py-2 font-semibold">GitHub username</th>
              <th className="px-3 py-2 font-semibold">Role</th>
              <th className="px-3 py-2 font-semibold">Invited by</th>
              <th className="px-3 py-2 font-semibold">Expires</th>
              <th className="px-3 py-2 font-semibold w-10" />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {invitations.map((inv) => (
              <tr key={inv.id} className="hover:bg-gray-800/30">
                <td className="px-3 py-2 font-mono text-[11px] text-gray-300">{inv.githubUsername}</td>
                <td className="px-3 py-2">
                  <span className="rounded bg-gray-800/60 px-2 py-0.5 font-mono text-[10px] text-gray-300">
                    {inv.role}
                  </span>
                </td>
                <td className="px-3 py-2 text-gray-400">
                  {inv.invitedBy ? (
                    <span className="inline-flex items-center gap-1.5">
                      {inv.invitedBy.avatarUrl && (
                        <img src={inv.invitedBy.avatarUrl} alt="" className="h-4 w-4 rounded-full ring-1 ring-gray-700" />
                      )}
                      {inv.invitedBy.username}
                    </span>
                  ) : (
                    <span className="text-gray-600 italic">—</span>
                  )}
                </td>
                <td className="px-3 py-2 text-[11px] text-gray-500 whitespace-nowrap">
                  {formatDate(inv.expiresAt)}
                </td>
                <td className="px-3 py-2 text-right">
                  <button
                    onClick={() => {
                      if (confirm(`Revoke invitation for ${inv.githubUsername}?`)) {
                        revoke.mutate(inv.id);
                      }
                    }}
                    disabled={revoke.isPending}
                    className="rounded p-1 text-gray-500 hover:bg-red-950/40 hover:text-red-300 disabled:opacity-40"
                    title="Revoke invitation"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
