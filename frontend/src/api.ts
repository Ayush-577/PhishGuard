import type { AnalysisReport, Explainer, QuizQuestion, Sample } from "./types";

async function readError(res: Response): Promise<string> {
  try {
    const data = await res.json();
    if (typeof data.detail === "string") return data.detail;
    return JSON.stringify(data.detail || data);
  } catch {
    return res.statusText;
  }
}

export async function analyzeText(text: string, sourceLabel = "pasted text"): Promise<AnalysisReport> {
  const res = await fetch("/api/analyze/text", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, source_label: sourceLabel }),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function analyzeFile(file: File): Promise<AnalysisReport> {
  const body = new FormData();
  body.append("file", file);
  const res = await fetch("/api/analyze/file", { method: "POST", body });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function fetchSamples(): Promise<Sample[]> {
  const res = await fetch("/api/samples");
  if (!res.ok) throw new Error(await readError(res));
  const data = await res.json();
  return data.samples;
}

export async function analyzeSample(id: string): Promise<AnalysisReport> {
  const res = await fetch(`/api/samples/${id}`, { method: "POST" });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function fetchQuiz(): Promise<QuizQuestion[]> {
  const res = await fetch("/api/learn/quiz");
  if (!res.ok) throw new Error(await readError(res));
  const data = await res.json();
  return data.questions;
}

export async function fetchExplainer(): Promise<Explainer> {
  const res = await fetch("/api/learn/explainer");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}
