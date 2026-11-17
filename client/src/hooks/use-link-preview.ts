import * as React from "react";
import { apiRequest } from "@/lib/queryClient";

export interface LinkPreview {
  title: string | null;
  description: string | null;
  status: number;
}

export function useLinkPreview() {
  const [preview, setPreview] = React.useState<LinkPreview | null>(null);
  const [loading, setLoading] = React.useState(false);

  const fetchPreview = React.useCallback(async (url: string) => {
    setLoading(true);
    try {
      const res = await apiRequest("GET", `/api/link-preview?url=${encodeURIComponent(url)}`);
      const data = (await res.json()) as LinkPreview;
      setPreview(data);
      return data;
    } finally {
      setLoading(false);
    }
  }, []);

  const onPaste = React.useCallback(
    (e: React.ClipboardEvent) => {
      const pasted = e.clipboardData.getData("text").trim();
      if (/^https?:\/\//i.test(pasted)) fetchPreview(pasted);
    },
    [fetchPreview],
  );

  return { preview, loading, fetchPreview, onPaste };
}
