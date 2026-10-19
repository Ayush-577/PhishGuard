import { useEffect, useState } from "react";
import { fetchExplainer, fetchQuiz } from "../api";
import type { Explainer, QuizQuestion } from "../types";

export function LearnPage() {
  const [explainer, setExplainer] = useState<Explainer | null>(null);
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [picked, setPicked] = useState<Record<string, number>>({});

  useEffect(() => {
    fetchExplainer().then(setExplainer).catch(() => setExplainer(null));
    fetchQuiz().then(setQuestions).catch(() => setQuestions([]));
  }, []);

  const score = questions.filter((q) => picked[q.id] === q.correct_index).length;
  const answered = Object.keys(picked).length;

  return (
    <>
      <div className="hero">
        <h2>Spot the phish</h2>
        <p>
          Scams work on the human layer: fear, urgency, authority and greed. Practice on realistic
          Indian samples, then read how the attack chain fits together.
        </p>
      </div>

      <section className="card" aria-labelledby="quiz-heading">
        <h2 id="quiz-heading">Mini-quiz</h2>
        <p className="meta">
          {answered ? `${score} / ${questions.length} correct so far` : "Instant feedback after each choice."}
        </p>
        {questions.map((q) => (
          <article key={q.id} className="quiz-q">
            <h3>{q.question}</h3>
            <p className="evidence">{q.sample}</p>
            <div className="options">
              {q.options.map((opt, index) => {
                const chosen = picked[q.id];
                const show = chosen !== undefined;
                const cls =
                  show && index === q.correct_index
                    ? "correct"
                    : show && index === chosen
                      ? "wrong"
                      : "";
                return (
                  <button
                    key={opt}
                    type="button"
                    className={cls}
                    disabled={show}
                    onClick={() => setPicked((prev) => ({ ...prev, [q.id]: index }))}
                  >
                    {opt}
                  </button>
                );
              })}
            </div>
            {picked[q.id] !== undefined && <p>{q.explanation}</p>}
          </article>
        ))}
      </section>

      {explainer && (
        <section className="card" aria-labelledby="learn-heading">
          <h2 id="learn-heading">{explainer.title}</h2>
          {explainer.sections.map((section) => (
            <div key={section.heading}>
              <h3>{section.heading}</h3>
              <p>{section.body}</p>
              {section.steps && (
                <ol className="steps">
                  {section.steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
              )}
            </div>
          ))}
        </section>
      )}
    </>
  );
}
