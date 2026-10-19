import { useEffect, useMemo, useState, type FormEvent } from "react";
import { analyzeFile, analyzeSample, analyzeText, fetchSamples } from "../api";
import type { AnalysisReport, Sample } from "../types";
import { ReportView } from "./ReportView";

const ALLOWED = [".eml", ".msg", ".txt", ".pdf", ".png", ".jpg", ".jpeg"];
const MAX = 10 * 1024 * 1024;

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function AnalyzePage() {
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);

  useEffect(() => {
    fetchSamples().then(setSamples).catch(() => setSamples([]));
  }, []);

  const fileLabel = useMemo(() => {
    if (!file) return null;
    return `${file.name} · ${formatBytes(file.size)}`;
  }, [file]);

  function accept(next: File | null) {
    setError(null);
    setReport(null);
    if (!next) {
      setFile(null);
      return;
    }
    const ext = "." + next.name.split(".").pop()?.toLowerCase();
    if (!ALLOWED.includes(ext)) {
      setError("Use .eml, .msg, .txt, .pdf, PNG or JPG.");
      return;
    }
    if (next.size > MAX) {
      setError("File is larger than 10 MB.");
      return;
    }
    setFile(next);
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const result = file ? await analyzeFile(file) : await analyzeText(text);
      setReport(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed.");
    } finally {
      setBusy(false);
    }
  }

  async function onSample(id: string) {
    setError(null);
    setBusy(true);
    setFile(null);
    try {
      const preview = samples.find((item) => item.id === id);
      if (preview) setText(preview.text);
      const result = await analyzeSample(id);
      setReport(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load sample.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="hero">
        <h2>Check a message before you tap.</h2>
        <p>
          Paste text, drop a screenshot, or upload an email file. Phish Check explains the red flags
          in plain language — built for Indian students and small businesses.
        </p>
      </div>
      <div className="warn-banner" role="note">
        Do not upload passwords, OTPs, card numbers, Aadhaar, or bank statements. We only need the
        suspicious wording or a screenshot of the lure itself.
      </div>

      <form className="card" onSubmit={onSubmit}>
        <label
          className={`drop ${over ? "over" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setOver(true);
          }}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setOver(false);
            accept(e.dataTransfer.files[0] ?? null);
          }}
        >
          <input
            type="file"
            accept=".eml,.msg,.txt,.pdf,.png,.jpg,.jpeg,image/png,image/jpeg"
            onChange={(e) => accept(e.target.files?.[0] ?? null)}
          />
          <strong>Drop a suspicious item</strong>
          <p className="meta">.eml, .msg, .txt, .pdf, PNG or JPG · max 10 MB</p>
        </label>
        {file && (
          <div className="file-chip">
            <span>{fileLabel}</span>
            <button type="button" className="btn btn-ghost" onClick={() => accept(null)}>
              Remove file
            </button>
          </div>
        )}

        <div style={{ marginTop: 16 }}>
          <label className="block" htmlFor="paste">
            Or paste the message or URL
          </label>
          <textarea
            id="paste"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="e.g. a KYC SMS, WhatsApp job offer, or a link you were asked to open"
            disabled={!!file}
          />
        </div>

        <div className="row">
          <button className="btn btn-primary" type="submit" disabled={busy || (!file && !text.trim())}>
            {busy ? "Checking…" : "Check this message"}
          </button>
          {samples.map((sample) => (
            <button
              key={sample.id}
              type="button"
              className="btn"
              disabled={busy}
              onClick={() => onSample(sample.id)}
            >
              Load sample: {sample.title}
            </button>
          ))}
        </div>
        {error && <p className="error">{error}</p>}
      </form>

      {report && (
        <div style={{ marginTop: 20 }}>
          <ReportView report={report} />
        </div>
      )}
    </>
  );
}
