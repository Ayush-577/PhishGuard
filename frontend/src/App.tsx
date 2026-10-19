import { useEffect, useState } from "react";
import { AnalyzePage } from "./components/AnalyzePage";
import { LearnPage } from "./components/LearnPage";

type Page = "check" | "learn";

function applyTheme(theme: "dark" | "light") {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("phish-check-theme", theme);
}

export default function App() {
  const [page, setPage] = useState<Page>("check");
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    const saved = localStorage.getItem("phish-check-theme");
    const next = saved === "light" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
  }

  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <div className="shell">
        <header className="topbar">
          <div className="brand">
            <div className="mark" aria-hidden="true">
              PC
            </div>
            <div>
              <h1>Phish Check</h1>
              <p>Working title: PhishGuard · Cybersecurity Challenge 2026</p>
            </div>
          </div>
          <nav className="nav" aria-label="Primary">
            <button type="button" aria-current={page === "check" ? "page" : undefined} onClick={() => setPage("check")}>
              Check a message
            </button>
            <button type="button" aria-current={page === "learn" ? "page" : undefined} onClick={() => setPage("learn")}>
              Learn &amp; quiz
            </button>
            <button type="button" className="btn-ghost" onClick={toggleTheme}>
              {theme === "dark" ? "Light mode" : "Dark mode"}
            </button>
          </nav>
        </header>
        <main id="main">{page === "check" ? <AnalyzePage /> : <LearnPage />}</main>
        <footer className="note">
          Rule-based helper for awareness. A low score is not proof of safety. Report fraud at
          cybercrime.gov.in or 1930.
        </footer>
      </div>
    </>
  );
}
