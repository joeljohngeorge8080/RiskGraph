import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { apiPost } from "@/api/client";
import type { Scan } from "@/api/types";
import { looksLikeGithubUrl } from "@/lib/format";

const EXAMPLES = [
  "https://github.com/bridgecrewio/terragoat",
  "https://github.com/OWASP/NodeGoat",
];

export function NewScanForm() {
  const [repoUrl, setRepoUrl] = useState("");
  const [ref, setRef] = useState("");
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const create = useMutation({
    mutationFn: () => apiPost<Scan>("/scans", { repo_url: repoUrl.trim(), ref: ref.trim() || null }),
    onSuccess: (scan) => {
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
      void navigate(`/scans/${scan.id}`);
    },
  });

  const valid = looksLikeGithubUrl(repoUrl);
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (valid) create.mutate();
  };

  return (
    <section className="panel">
      <h1>Scan a GitHub repository</h1>
      <p className="muted">
        Clones a public repository, runs Trivy, Semgrep, Checkov and Gitleaks, merges what they find
        into one list and ranks it by risk.
      </p>
      <form onSubmit={onSubmit} className="row">
        <input
          type="url"
          placeholder="https://github.com/owner/repository"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          aria-label="Repository URL"
          required
        />
        <input
          type="text"
          placeholder="branch or tag (optional)"
          value={ref}
          onChange={(e) => setRef(e.target.value)}
          aria-label="Branch or tag"
          style={{ width: 200 }}
        />
        <button type="submit" disabled={!valid || create.isPending}>
          {create.isPending ? "Starting…" : "Start scan"}
        </button>
      </form>
      {repoUrl && !valid && (
        <p className="muted">Use a public URL like https://github.com/owner/repository</p>
      )}
      {create.isError && <p className="error">{create.error.message}</p>}
      <p className="muted" style={{ marginBottom: 0 }}>
        Try:{" "}
        {EXAMPLES.map((url) => (
          <button key={url} type="button" className="secondary" style={{ marginRight: 6, padding: "0.1rem 0.5rem" }} onClick={() => setRepoUrl(url)}>
            {url.replace("https://github.com/", "")}
          </button>
        ))}
      </p>
    </section>
  );
}
