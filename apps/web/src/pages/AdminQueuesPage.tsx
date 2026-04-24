/**
 * Admin — BullMQ queue viewer + dead-letter tools.
 *
 * Ops use-case: when a scan job silently fails (scanner OOM, AI provider
 * rate-limit, Prisma deadlock), BullMQ keeps the failed attempt in the
 * queue's `failed` set for a while. Without this page the only way to see
 * them is `docker exec redis redis-cli`. With it an operator can inspect the
 * stacktrace, retry, or drop the job — no shell required.
 *
 * RBAC: backend routes are gated to ADMIN+, so a non-admin hitting this
 * page will just see 403s; we also hide the nav entry in Layout.tsx.
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Layers, RefreshCw, Trash2, AlertTriangle, ChevronRight } from "lucide-react";
import { adminApi, type FailedJob, type QueueCounts } from "../lib/api";
import { formatRelative } from "../lib/utils";

/** Highlight queues whose failed count > 0. */
function countTone(kind: keyof QueueCounts, n: number): string {
  if (n === 0) return "text-gray-600";
  if (kind === "failed")  return "text-rose-400 font-semibold";
  if (kind === "active")  return "text-indigo-300";
  if (kind === "waiting" || kind === "delayed") return "text-amber-400";
  return "text-gray-300";
}

export default function AdminQueuesPage() {
  const qc = useQueryClient();

  const { data: queues, isLoading } = useQuery({
    queryKey: ["admin", "queues"],
    queryFn:  adminApi.listQueues,
    refetchInterval: 5_000,
  });

  const [activeQueue, setActiveQueue] = useState<string | null>(null);

  return (
    <div className="flex h-full flex-col p-6">
      <div className="mb-5">
        <h1 className="flex items-center gap-2 text-3xl font-bold text-white">
          <Layers className="h-7 w-7 text-indigo-400" />
          Queues
        </h1>
        <p className="mt-0.5 text-xs text-gray-500">
          Live BullMQ counters + failed-job viewer. Failed jobs older than the
          queue retention window are pruned automatically.
        </p>
      </div>

      {/* Queue counters */}
      <div className="mb-5 overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-800 bg-gray-900 text-left text-xs text-gray-500">
            <tr>
              <th className="px-4 py-2 font-medium">Queue</th>
              <th className="px-3 py-2 font-medium">Waiting</th>
              <th className="px-3 py-2 font-medium">Active</th>
              <th className="px-3 py-2 font-medium">Delayed</th>
              <th className="px-3 py-2 font-medium">Completed</th>
              <th className="px-3 py-2 font-medium">Failed</th>
              <th className="px-3 py-2 font-medium">Paused</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-900/50 text-xs tabular-nums">
            {isLoading ? (
              <tr><td colSpan={8} className="py-8 text-center text-gray-500">Loading…</td></tr>
            ) : !queues?.length ? (
              <tr><td colSpan={8} className="py-8 text-center text-gray-500">No queues.</td></tr>
            ) : queues.map((q) => (
              <tr
                key={q.name}
                className={`cursor-pointer hover:bg-gray-800/40 ${activeQueue === q.name ? "bg-indigo-950/30" : ""}`}
                onClick={() => setActiveQueue(q.name)}
              >
                <td className="px-4 py-2 font-mono text-gray-300">{q.name}</td>
                <td className={`px-3 py-2 ${countTone("waiting",   q.counts.waiting)}`}>{q.counts.waiting}</td>
                <td className={`px-3 py-2 ${countTone("active",    q.counts.active)}`}>{q.counts.active}</td>
                <td className={`px-3 py-2 ${countTone("delayed",   q.counts.delayed)}`}>{q.counts.delayed}</td>
                <td className={`px-3 py-2 ${countTone("completed", q.counts.completed)}`}>{q.counts.completed}</td>
                <td className={`px-3 py-2 ${countTone("failed",    q.counts.failed)}`}>{q.counts.failed}</td>
                <td className={`px-3 py-2 ${countTone("paused",    q.counts.paused)}`}>{q.counts.paused}</td>
                <td className="px-3 py-2 text-right">
                  <ChevronRight className={`inline h-3 w-3 transition-transform ${activeQueue === q.name ? "rotate-90 text-indigo-400" : "text-gray-600"}`} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Failed-job list for the selected queue */}
      {activeQueue && (
        <FailedJobsPanel
          queueName={activeQueue}
          onMutate={() => {
            qc.invalidateQueries({ queryKey: ["admin", "queues"] });
            qc.invalidateQueries({ queryKey: ["admin", "failed", activeQueue] });
          }}
        />
      )}
    </div>
  );
}

function FailedJobsPanel({
  queueName, onMutate,
}: {
  queueName: string;
  onMutate: () => void;
}) {
  const { data: jobs, isLoading } = useQuery({
    queryKey: ["admin", "failed", queueName],
    queryFn:  () => adminApi.listFailed(queueName, 50),
    refetchInterval: 10_000,
  });

  const retry = useMutation({
    mutationFn: (jobId: string) => adminApi.retryJob(queueName, jobId),
    onSuccess: onMutate,
  });
  const drop = useMutation({
    mutationFn: (jobId: string) => adminApi.deleteJob(queueName, jobId),
    onSuccess: onMutate,
  });

  return (
    <div className="flex-1 overflow-hidden rounded-lg border border-gray-800">
      <div className="flex items-center justify-between border-b border-gray-800 bg-gray-900 px-4 py-2">
        <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
          <AlertTriangle className="h-4 w-4 text-rose-400" />
          Failed jobs — <span className="font-mono text-indigo-300">{queueName}</span>
        </div>
        <span className="text-xs text-gray-500">showing most recent 50</span>
      </div>

      <div className="max-h-[55vh] overflow-auto">
        {isLoading ? (
          <div className="flex h-40 items-center justify-center text-gray-500">Loading…</div>
        ) : !jobs?.length ? (
          <div className="flex h-40 items-center justify-center text-sm text-gray-500">
            No failed jobs in this queue 🎉
          </div>
        ) : (
          <ul className="divide-y divide-gray-800">
            {jobs.map((j) => (
              <FailedJobRow
                key={j.id}
                job={j}
                busy={retry.isPending || drop.isPending}
                onRetry={() => retry.mutate(j.id)}
                onDrop={() => {
                  if (confirm(`Permanently drop failed job ${j.id}? This cannot be undone.`)) {
                    drop.mutate(j.id);
                  }
                }}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function FailedJobRow({
  job, busy, onRetry, onDrop,
}: {
  job: FailedJob;
  busy: boolean;
  onRetry: () => void;
  onDrop: () => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <li className="px-4 py-3 text-xs">
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-gray-300">{job.id}</span>
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{job.name}</span>
            <span className="text-[10px] text-gray-500">
              attempts: <span className="text-gray-300">{job.attemptsMade}</span>
            </span>
            <span className="text-[10px] text-gray-500">
              failed: {job.finishedOn ? formatRelative(new Date(job.finishedOn).toISOString()) : "—"}
            </span>
          </div>
          {job.failedReason && (
            <p className="mt-1 truncate text-rose-300" title={job.failedReason}>
              {job.failedReason}
            </p>
          )}
          {open && (
            <div className="mt-2 space-y-2">
              {job.stacktrace?.length ? (
                <pre className="max-h-48 overflow-auto rounded bg-black/40 p-2 font-mono text-[11px] text-rose-200">
                  {job.stacktrace.join("\n")}
                </pre>
              ) : null}
              <pre className="max-h-48 overflow-auto rounded bg-black/40 p-2 font-mono text-[11px] text-gray-300">
                {JSON.stringify(job.data, null, 2)}
              </pre>
            </div>
          )}
          <button
            onClick={() => setOpen((v) => !v)}
            className="mt-1 text-[11px] text-indigo-400 hover:text-indigo-200"
          >
            {open ? "Hide details" : "Show stack + payload"}
          </button>
        </div>
        <div className="flex flex-col gap-1">
          <button
            onClick={onRetry}
            disabled={busy}
            className="inline-flex items-center gap-1 rounded border border-indigo-800 bg-indigo-950/50 px-2 py-1 text-[11px] text-indigo-200 hover:bg-indigo-900/60 disabled:opacity-40"
            title="Move this job back to waiting"
          >
            <RefreshCw className="h-3 w-3" /> Retry
          </button>
          <button
            onClick={onDrop}
            disabled={busy}
            className="inline-flex items-center gap-1 rounded border border-rose-900 bg-rose-950/40 px-2 py-1 text-[11px] text-rose-200 hover:bg-rose-900/60 disabled:opacity-40"
            title="Permanently remove this failed job"
          >
            <Trash2 className="h-3 w-3" /> Drop
          </button>
        </div>
      </div>
    </li>
  );
}
