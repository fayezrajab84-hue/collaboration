import { useState, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileJson, Trash2, Upload, ChevronDown, ChevronUp, CheckCircle2 } from "lucide-react";
import { domainsApi } from "../lib/api";

interface Props {
  domainId: string;
}

export default function DomainApiSpecPanel({ domainId }: Props) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const { data: existing } = useQuery({
    queryKey: ["domain-apispec", domainId],
    queryFn: () => domainsApi.getApiSpec(domainId),
    enabled: open,
  });

  const save = useMutation({
    mutationFn: (data: { filename: string; specJson: Record<string, unknown> }) =>
      domainsApi.saveApiSpec(domainId, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["domain-apispec", domainId] }),
  });

  const remove = useMutation({
    mutationFn: () => domainsApi.deleteApiSpec(domainId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["domain-apispec", domainId] }),
  });

  const handleFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const specJson = JSON.parse(e.target?.result as string);
        save.mutate({ filename: file.name, specJson });
      } catch {
        alert("Invalid JSON — please upload a valid OpenAPI/Swagger JSON file.");
      }
    };
    reader.readAsText(file);
  };

  const hasSpec = existing != null;

  return (
    <div className="mt-2 rounded-lg border border-gray-700/60 bg-gray-800/40">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-left"
      >
        <div className="flex items-center gap-2">
          <FileJson className="h-3.5 w-3.5 text-violet-400" />
          <span className="text-xs font-medium text-gray-300">API Spec (OpenAPI / Swagger)</span>
          {hasSpec && (
            <span className="flex items-center gap-1 rounded-full bg-violet-900/50 px-2 py-0.5 text-[10px] font-medium text-violet-300">
              <CheckCircle2 className="h-3 w-3" />
              {existing.endpoints} endpoints · {existing.filename}
            </span>
          )}
        </div>
        {open ? <ChevronUp className="h-3.5 w-3.5 text-gray-500" /> : <ChevronDown className="h-3.5 w-3.5 text-gray-500" />}
      </button>

      {open && (
        <div className="border-t border-gray-700/60 px-4 pb-4 pt-3 space-y-3">
          {/* Drop zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const file = e.dataTransfer.files[0];
              if (file) handleFile(file);
            }}
            onClick={() => fileRef.current?.click()}
            className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-4 py-6 transition-colors ${
              dragOver ? "border-violet-500 bg-violet-900/20" : "border-gray-700 hover:border-violet-600/60"
            }`}
          >
            <Upload className="mb-2 h-5 w-5 text-gray-500" />
            <p className="text-xs text-gray-400">
              Drop <span className="font-mono">openapi.json</span> / <span className="font-mono">swagger.json</span> here, or click to browse
            </p>
            <p className="mt-1 text-[10px] text-gray-600">OpenAPI 3.x and Swagger 2.x supported</p>
            <input
              ref={fileRef}
              type="file"
              accept=".json,.yaml,.yml"
              className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
            />
          </div>

          {save.isPending && (
            <p className="text-xs text-violet-400 animate-pulse">Uploading…</p>
          )}
          {save.isSuccess && (
            <p className="text-xs text-teal-400 flex items-center gap-1">
              <CheckCircle2 className="h-3 w-3" /> Spec saved — {existing?.endpoints ?? "?"} endpoints extracted. Next scan will target all API paths.
            </p>
          )}
          {save.isError && (
            <p className="text-xs text-red-400">{(save.error as Error).message}</p>
          )}

          {hasSpec && (
            <div className="flex items-center justify-between rounded bg-gray-900/60 px-3 py-2">
              <div>
                <p className="text-xs font-medium text-gray-200">{existing.filename}</p>
                <p className="text-[10px] text-gray-500">{existing.endpoints} endpoints indexed</p>
              </div>
              <button
                onClick={() => remove.mutate()}
                disabled={remove.isPending}
                className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300 disabled:opacity-50"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Remove
              </button>
            </div>
          )}

          <p className="text-[10px] text-gray-600">
            DAST and pentest scans will automatically target all imported API endpoints in addition to crawled URLs.
          </p>
        </div>
      )}
    </div>
  );
}
