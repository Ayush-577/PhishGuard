import type { UrlPart } from "../types";

export function UrlBreakdown({ urls }: { urls: UrlPart[] }) {
  if (!urls.length) return null;
  return (
    <section className="card" aria-labelledby="url-heading">
      <h2 id="url-heading">Link breakdown</h2>
      <p className="meta">
        The highlighted domain is the real website. Words on the left are just decoration.
      </p>
      {urls.map((url) => (
        <div key={url.original}>
          <p className="evidence">{url.original}</p>
          <div className="url-break" aria-label="Parts of the URL">
            <div className={`part ${url.uses_https ? "ok" : ""}`}>
              <strong>Protocol</strong>
              {url.protocol || "none"}
            </div>
            <div className="part">
              <strong>Subdomain</strong>
              {url.subdomain || "—"}
            </div>
            <div className="part domain">
              <strong>Real domain</strong>
              {url.domain || url.host || "—"}
            </div>
            <div className="part">
              <strong>Path</strong>
              {(url.path || "/") + (url.query ? `?${url.query}` : "")}
            </div>
          </div>
        </div>
      ))}
    </section>
  );
}
