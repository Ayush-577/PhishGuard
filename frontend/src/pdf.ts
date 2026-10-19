import { jsPDF } from "jspdf";
import type { AnalysisReport } from "./types";

export function exportReportPdf(report: AnalysisReport) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const margin = 48;
  const width = 595 - margin * 2;
  let y = margin;

  const write = (text: string, size = 11, gap = 16) => {
    doc.setFontSize(size);
    const lines = doc.splitTextToSize(text, width) as string[];
    for (const line of lines) {
      if (y > 780) {
        doc.addPage();
        y = margin;
      }
      doc.text(line, margin, y);
      y += gap;
    }
  };

  write("Phish Check report", 18, 22);
  write(`${report.verdict_label}  ·  score ${report.score}/100`, 13, 18);
  write(`Analysed ${report.analyzed_at}  ·  input: ${report.input_kind}`, 10, 14);
  write(report.disclaimer, 10, 14);
  y += 8;
  write("Findings", 14, 18);
  if (!report.findings.length) {
    write("No rule-based red flags. This is not proof of safety.");
  }
  for (const finding of report.findings) {
    write(`${finding.severity.toUpperCase()} — ${finding.title}`, 12, 16);
    write(finding.explanation, 10, 14);
    if (finding.evidence) write(`Evidence: ${finding.evidence}`, 9, 12);
    y += 6;
  }
  write("What to do", 14, 18);
  report.what_to_do.forEach((item, i) => write(`${i + 1}. ${item}`, 10, 14));
  y += 8;
  write("External checks", 14, 18);
  for (const check of report.external_checks) {
    write(
      `${check.name}: ${check.status.replaceAll("_", " ")} — ${check.summary} (source: ${check.source}${check.checked_at ? `; ${check.checked_at}` : ""})`,
      10,
      14
    );
  }
  if (report.upload_deleted) {
    y += 6;
    write("Uploaded file was deleted from the server right after analysis.", 10, 14);
  }
  doc.save(`phish-check-${report.score}.pdf`);
}
