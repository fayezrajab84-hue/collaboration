import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Ticket as TicketIcon } from "lucide-react";
import { ticketsApi } from "../lib/api";
import type { Ticket } from "@devsecops/types";
import SeverityBadge from "../components/SeverityBadge";
import { formatRelative } from "../lib/utils";

const COLUMNS = [
  { status: "OPEN",        label: "Open",        color: "border-red-800" },
  { status: "IN_PROGRESS", label: "In Progress",  color: "border-amber-700" },
  { status: "RESOLVED",    label: "Resolved",     color: "border-teal-800" },
  { status: "CLOSED",      label: "Closed",       color: "border-gray-700" },
];

function TicketCard({ ticket }: { ticket: Ticket }) {
  const qc = useQueryClient();
  const update = useMutation({
    mutationFn: (status: string) => ticketsApi.update(ticket.id, { status: status as never }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tickets"] }),
  });

  const finding = (ticket as unknown as { finding?: { severity?: string; scanType?: string } }).finding;

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800/60 p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <p className="text-sm font-medium text-gray-100 leading-snug">{ticket.title}</p>
        {finding?.severity && <SeverityBadge severity={finding.severity} />}
      </div>

      {finding?.scanType && (
        <span className="inline-block rounded bg-gray-700 px-2 py-0.5 text-xs text-gray-400">
          {finding.scanType}
        </span>
      )}

      {ticket.jiraKey && (
        <a href={ticket.jiraUrl ?? "#"} target="_blank" rel="noreferrer"
          className="flex items-center gap-1 text-xs text-blue-400 hover:underline">
          {ticket.jiraKey}
        </a>
      )}

      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500">{formatRelative(ticket.createdAt)}</span>
        <select
          value={ticket.status}
          onChange={(e) => update.mutate(e.target.value)}
          className="rounded bg-gray-700 px-2 py-1 text-xs text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          onClick={(e) => e.stopPropagation()}
        >
          <option value="OPEN">Open</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="RESOLVED">Resolved</option>
          <option value="CLOSED">Closed</option>
        </select>
      </div>
    </div>
  );
}

export default function TicketsPage() {
  const { data: ticketData, isLoading } = useQuery({
    queryKey: ["tickets"],
    queryFn: () => ticketsApi.list({ limit: 100 }),
  });

  const tickets = ticketData?.data ?? [];

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center text-gray-500">Loading…</div>
    );
  }

  if (tickets.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-gray-500 p-6">
        <TicketIcon className="h-10 w-10" />
        <p className="text-sm">No tickets yet.</p>
        <p className="text-xs text-gray-600">Open a finding and click "Create Ticket" to track remediation.</p>
      </div>
    );
  }

  return (
    <div className="p-6">
      <h1 className="mb-6 text-3xl font-bold text-white">Tickets</h1>

      {/* Kanban board */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {COLUMNS.map(({ status, label, color }) => {
          const col = tickets.filter((t) => t.status === status);
          return (
            <div key={status} className={`rounded-xl border-t-2 ${color} bg-gray-900 p-4`}>
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-sm font-semibold text-gray-200">{label}</h2>
                <span className="rounded-full bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {col.length}
                </span>
              </div>
              <div className="space-y-3">
                {col.map((ticket) => (
                  <TicketCard key={ticket.id} ticket={ticket} />
                ))}
                {col.length === 0 && (
                  <p className="py-6 text-center text-xs text-gray-600">No tickets yet.</p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
