import { useEffect, useRef, useState } from "react";

interface SseEvent {
  type: string;
  status?: string;
  scanType?: string;
  count?: number;
  severityBreakdown?: Record<string, number>;
  error?: string;
  [key: string]: unknown;
}

export function useSSE(scanJobId: string | null) {
  const [latestEvent, setLatestEvent] = useState<SseEvent | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!scanJobId) return;

    const es = new EventSource(`/api/scans/${scanJobId}/events`, { withCredentials: true });
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const event: SseEvent = JSON.parse(e.data);
        setLatestEvent(event);
        if (event.status) setStatus(event.status);
        if (event.type === "INITIAL" && event.status) setStatus(event.status as string);
      } catch {
        // ignore parse errors
      }
    };

    es.onerror = () => {
      es.close();
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [scanJobId]);

  return { latestEvent, status };
}
