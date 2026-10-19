import { exportReportPdf } from "../pdf";
import type { AnalysisReport, Lever } from "../types";
import { UrlBreakdown } from "./UrlBreakdown";

const LEVER_LABEL: Record<Lever, string> = {
  urgency: "Urgency",
  fear: "Fear",
  authority: "Authority",
  greed: "Greed",
  curiosity: "Curiosity",
  none: "No social lever tagged",
};

const STATUS_LABEL: Record<string, string> = {
  ok: "Ran",
  not_connected: "Not connected",
  could_not_run: "Could not run",
  skipped: "Skipped",
};

function formatBytes(n: number | null) {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function ReportView({ report }: { report: AnalysisReport }) {
  return (
    <div className="grid" id="report">
      <section className="card verdict" aria-labelledby="verdict-heading">
        <div className={`score-ring ${report.verdict}`} aria-hidden="true">
          {report.score}
        </div>
        <div>
          <p className={`badge ${report.verdict}`}>{report.verdict} risk</p>
          <h2 id="verdict-heading">{report.verdict_label}</h2>
          <p className="meta">
            {report.analyzed_at}
            {report.filename
              ? ` · ${report.filename} (${formatBytes(report.filesize)})`
              : ` · ${report.input_kind}`}
          </p>
          <p>{report.disclaimer}</p>
          {report.upload_deleted && (
            <p className="meta">Your upload was deleted from the server immediately after analysis.</p>
          )}
          <div className="row">
            <button className="btn" type="button" onClick={() => exportReportPdf(report)}>
              Export report as PDF
            </button>
          </div>
        </div>
      </section>

      <UrlBreakdown urls={report.urls} />

      <section className="card" aria-labelledby="findings-heading">
        <h2 id="findings-heading">Findings</h2>
        {!report.findings.length && (
          <p>No rule-based red flags. This is not proof of safety — verify through official channels.</p>
        )}
        {report.findings.map((finding) => (
          <article key={finding.id} className={`finding ${finding.severity}`}>
            <p className={`badge ${finding.severity}`}>{finding.severity}</p>
            <h3>{finding.title}</h3>
            <p>{finding.explanation}</p>
            <p className="meta">
              Psychological lever: {LEVER_LABEL[finding.lever]} · category {finding.category}
            </p>
            {finding.evidence && <p className="evidence">{finding.evidence}</p>}
          </article>
        ))}
      </section>

      <section className="card" aria-labelledby="todo-heading">
        <h2 id="todo-heading">What to do</h2>
        <ol className="ol-actions">
          {report.what_to_do.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ol>
        <p>
          Report:{" "}
          <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">
            cybercrime.gov.in
          </a>{" "}
          · helpline 1930
        </p>
      </section>

      {!!report.attachments.length && (
        <section className="card">
          <h2>Attachments (names only — never opened)</h2>
          <ul>
            {report.attachments.map((att) => (
              <li key={att.filename}>
                {att.filename} {att.content_type ? `(${att.content_type})` : ""}
              </li>
            ))}
          </ul>
        </section>
      )}

      {!!report.external_checks.length && (
        <section className="card" aria-labelledby="ext-heading">
          <h2 id="ext-heading">External checks</h2>
          <p className="meta">We never invent a result. Missing keys show as Not connected.</p>
          <div className="checks">
            {report.external_checks.map((check) => (
              <div key={check.name} className={`check ${check.status}`}>
                <strong>{check.name}</strong> · {STATUS_LABEL[check.status]}
                <p>{check.summary}</p>
                <p className="meta">
                  Source: {check.source}
                  {check.checked_at ? ` · ${check.checked_at}` : ""}
                </p>
              </div>
            ))}
          </div>
        </section>
      )}

      {report.extracted_text && (
        <section className="card">
          <h2>Text we analysed</h2>
          <p className="evidence">{report.extracted_text}</p>
        </section>
      )}
    </div>
  );
}
