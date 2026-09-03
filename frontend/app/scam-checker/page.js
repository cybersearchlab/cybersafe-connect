"use client";

import { useEffect, useState } from "react";
import { getAuth, authHeader } from "../../lib/auth";
import { parseApiError } from "../../lib/apiError";
import BackLink from "../BackLink";
import { T, LangToggle, readStoredLang, storeLang } from "./i18n";

const API_URL =
  process.env.NEXT_PUBLIC_SCAM_CHECKER_URL || "http://localhost:8002";

const MAX_EVIDENCE_FILES = 5;
const ALLOWED_EVIDENCE_TYPES = ["image/png", "image/jpeg", "image/webp", "application/pdf"];

function guessReportType(content, isUrl) {
  if (isUrl) return "url";
  return "phone";
}

function guessReportValue(content, isUrl) {
  if (isUrl) return content.trim();
  const phoneMatch = content.match(/(?:\+?237)?\s?6\d{2}\s?\d{2}\s?\d{2}\s?\d{2}/);
  return phoneMatch ? phoneMatch[0].replace(/[\s+]/g, "").replace(/^237/, "") : "";
}

export default function ScamCheckerPage() {
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [lang, setLang] = useState("fr");
  const t = T[lang];

  const [auth, setAuth] = useState(null);
  const [reportType, setReportType] = useState("phone");
  const [reportValue, setReportValue] = useState("");
  const [reportDescription, setReportDescription] = useState("");
  const [evidenceFiles, setEvidenceFiles] = useState([]);
  const [reportStatus, setReportStatus] = useState(null);
  const [reportError, setReportError] = useState(null);
  const [reportSubmitting, setReportSubmitting] = useState(false);

  useEffect(() => {
    setAuth(getAuth());
    setLang(readStoredLang());
  }, []);

  function changeLang(next) {
    setLang(next);
    storeLang(next);
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (!content.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setReportStatus(null);
    setReportError(null);

    try {
      const response = await fetch(`${API_URL}/scam/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, lang }),
      });

      const body = await response.json();

      if (!response.ok || !body.success) {
        setError(parseApiError(body, t.checkErrorFallback));
        return;
      }

      setResult(body.data);
      setReportType(guessReportType(content, body.data.is_url));
      setReportValue(guessReportValue(content, body.data.is_url));
      setReportDescription(content);
    } catch {
      setError(t.checkNetworkError);
    } finally {
      setLoading(false);
    }
  }

  function handleEvidenceChange(event) {
    const files = Array.from(event.target.files || []);
    const accepted = [];
    for (const file of files) {
      if (!ALLOWED_EVIDENCE_TYPES.includes(file.type)) {
        setReportError(t.evidenceRejected(file.name));
        continue;
      }
      accepted.push(file);
    }
    setEvidenceFiles(accepted.slice(0, MAX_EVIDENCE_FILES));
  }

  async function handleReport(event) {
    event.preventDefault();
    if (!reportValue.trim()) return;

    setReportStatus(null);
    setReportError(null);
    setReportSubmitting(true);

    try {
      const response = await fetch(`${API_URL}/scam/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({
          type: reportType,
          value: reportValue.trim(),
          description: reportDescription.trim() || null,
        }),
      });
      const body = await response.json();

      if (!response.ok || !body.success) {
        setReportError(parseApiError(body, t.reportErrorFallback));
        return;
      }

      // Les preuves sont envoyées dans un second temps, une fois le
      // signalement créé — POST /scam/report/{report_id}/evidence attend un
      // identifiant qui n'existe qu'après cette première requête.
      const reportId = body.data.report_id;
      let uploadFailures = 0;
      for (const file of evidenceFiles) {
        const formData = new FormData();
        formData.append("file", file);
        const uploadResponse = await fetch(`${API_URL}/scam/report/${reportId}/evidence`, {
          method: "POST",
          headers: { ...authHeader() },
          body: formData,
        });
        if (!uploadResponse.ok) uploadFailures += 1;
      }

      let message = t.reportSuccess(body.data.report_count);
      if (evidenceFiles.length > 0) {
        message +=
          uploadFailures === 0
            ? t.evidenceAttachedOk(evidenceFiles.length)
            : t.evidenceAttachedPartial(evidenceFiles.length - uploadFailures, evidenceFiles.length, uploadFailures);
      }
      setReportStatus(message);
      setReportValue("");
      setReportDescription("");
      setEvidenceFiles([]);
    } catch {
      setReportError(t.serviceUnreachable);
    } finally {
      setReportSubmitting(false);
    }
  }

  return (
    <main className="main">
      <BackLink label={t.backToHome} />

      <section className="hero">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <h1 style={{ margin: 0 }}>{t.checkTitle}</h1>
          <LangToggle lang={lang} onChange={changeLang} />
        </div>
        <p>{t.checkSubtitle}</p>
        <p className="footer-note">{t.checkLangNote}</p>
      </section>

      <form className="card" onSubmit={handleSubmit}>
        <textarea
          placeholder={t.checkPlaceholder}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          maxLength={2000}
        />
        <button type="submit" className="primary" disabled={loading || !content.trim()}>
          {loading ? t.checkButtonLoading : t.checkButton}
        </button>
      </form>

      {error && <div className="error-banner">{error}</div>}

      {result && (
        <div className="result">
          <div className={`result-header ${result.verdict}`}>
            <span className="verdict">
              {result.verdict} — {t.verdictLabels[result.verdict]}
            </span>
            <span className="score">{t.scoreLabel} : {result.score}</span>
          </div>
          <div className="result-body">
            {result.motifs && result.motifs.length > 0 && (
              <>
                <h3>{t.motifsHeading}</h3>
                <div style={{ marginBottom: 20 }}>
                  {result.motifs.map((motif) => (
                    <span key={motif} className="motif-tag">
                      {motif}
                    </span>
                  ))}
                </div>
              </>
            )}

            <h3>{t.conseilsHeading}</h3>
            <ul>
              {result.conseils.map((conseil) => (
                <li key={conseil}>{conseil}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Carte séparée et toujours visible dès qu'on est connecté — sortie de
          la section signalement pour qu'un utilisateur qui veut seulement
          CONSULTER la liste noire (sans rien signaler) la trouve tout de
          suite, sans avoir à ouvrir le formulaire de signalement pour la
          repérer (retour utilisateur du 02/09/2026). */}
      {auth?.user && (
        <div className="card" style={{ marginBottom: 20 }}>
          <strong>{t.consultTitle}</strong>
          <p style={{ color: "var(--muted)", margin: "6px 0 12px" }}>{t.consultDesc}</p>
          <a href="/scam-checker/liste" className="btn-link-primary">
            {t.consultButton}
          </a>
        </div>
      )}

      {/* Toujours visible dès qu'on est connecté — pas seulement après avoir
          vérifié un message avec un verdict suspect. Un utilisateur connecté
          doit pouvoir signaler un numéro/lien connu comme frauduleux à tout
          moment, sans devoir d'abord déclencher une vérification. */}
      <div className="report-section">
        <strong>{t.reportSectionTitle}</strong>
        {auth?.user ? (
          <form onSubmit={handleReport}>
            <div className="row">
              <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
                <option value="phone">{t.typePhone}</option>
                <option value="url">{t.typeUrl}</option>
                <option value="domain">{t.typeDomain}</option>
              </select>
              <input
                type="text"
                value={reportValue}
                onChange={(e) => setReportValue(e.target.value)}
                placeholder={t.valueToReportPlaceholder}
                required
              />
            </div>

            <label>{t.modeOperatoireLabel}</label>
            <textarea
              value={reportDescription}
              onChange={(e) => setReportDescription(e.target.value)}
              placeholder={t.modeOperatoirePlaceholder}
              maxLength={1000}
              style={{ minHeight: 90 }}
            />

            <label>{t.evidenceLabel}</label>
            <input
              type="file"
              accept="image/png,image/jpeg,image/webp,application/pdf"
              multiple
              onChange={handleEvidenceChange}
            />
            {evidenceFiles.length > 0 && (
              <ul className="evidence-file-list">
                {evidenceFiles.map((f) => (
                  <li key={f.name}>{f.name}</li>
                ))}
              </ul>
            )}

            <button
              type="submit"
              className="primary"
              disabled={reportSubmitting}
              style={{ marginTop: 14 }}
            >
              {reportSubmitting ? t.reportButtonSending : t.reportButton}
            </button>

            {reportStatus && <p className="report-success">{reportStatus}</p>}
            {reportError && <div className="error-banner">{reportError}</div>}
          </form>
        ) : (
          <p>
            <a href="/login">{t.loginLink}</a> {t.loginPromptSuffix}
          </p>
        )}
      </div>

      <p className="footer-note">{t.footerVigilance}</p>
      <p className="footer-note">{t.footerMobileMoney}</p>
    </main>
  );
}
