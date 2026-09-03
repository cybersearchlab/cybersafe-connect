"use client";

import { Fragment, useEffect, useState } from "react";
import { getAuth, authHeader } from "../../../lib/auth";
import { parseApiError } from "../../../lib/apiError";
import BackLink from "../../BackLink";
import { T, LangToggle, readStoredLang, storeLang } from "../i18n";

const API_URL =
  process.env.NEXT_PUBLIC_SCAM_CHECKER_URL || "http://localhost:8002";

export default function BlacklistPage() {
  const [auth, setAuth] = useState(null);
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [lang, setLang] = useState("fr");
  const t = T[lang];

  useEffect(() => {
    const currentAuth = getAuth();
    setAuth(currentAuth);
    setLang(readStoredLang());
    if (!currentAuth?.user) return;

    fetch(`${API_URL}/scam/blacklist`, { headers: { ...authHeader() } })
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok || !body.success) {
          setError(parseApiError(body, t.listeLoadError));
          return;
        }
        setEntries(body.data);
      })
      .catch(() => setError(t.serviceUnreachable));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function changeLang(next) {
    setLang(next);
    storeLang(next);
  }

  const typeLabels = { phone: t.typePhone, url: t.typeUrl, domain: t.typeDomain };
  const locale = lang === "fr" ? "fr-FR" : "en-US";

  return (
    <main className="main">
      <BackLink href="/scam-checker" label={t.backToScamChecker} />

      <section className="hero">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <h1 style={{ margin: 0 }}>{t.listeTitle}</h1>
          <LangToggle lang={lang} onChange={changeLang} />
        </div>
        <p>{t.listeSubtitle}</p>
      </section>

      {!auth?.user && (
        <div className="card">
          <p>
            <a href="/login">{t.loginLink}</a> {t.listeLoginPromptSuffix}
          </p>
        </div>
      )}

      {auth?.user && error && <div className="error-banner">{error}</div>}

      {auth?.user && entries && entries.length === 0 && (
        <div className="card">
          <p>{t.listeEmpty}</p>
        </div>
      )}

      {auth?.user && entries && entries.length > 0 && (
        <>
          <p className="entry-expand-hint">{t.expandHint}</p>
          <div className="entries-table-wrap">
            <table className="entries-table">
              <thead>
                <tr>
                  <th>{t.colType}</th>
                  <th>{t.colValue}</th>
                  <th>{t.colReports}</th>
                  <th>{t.colReason}</th>
                  <th>{t.colUpdated}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => {
                  const expanded = expandedId === entry.id;
                  return (
                    <Fragment key={entry.id}>
                      <tr
                        className="entry-row"
                        aria-expanded={expanded}
                        onClick={() => setExpandedId(expanded ? null : entry.id)}
                      >
                        <td>{typeLabels[entry.type]}</td>
                        <td><strong>{entry.value}</strong></td>
                        <td>{t.listeReportCount(entry.report_count)}</td>
                        <td className="entry-reason-cell">{entry.admin_reason || t.reasonNotProvided}</td>
                        <td>{new Date(entry.updated_at).toLocaleString(locale)}</td>
                      </tr>
                      {expanded && (
                        <tr>
                          <td colSpan={5} className="entry-detail-cell">
                            {entry.description ? (
                              <p className="blacklist-entry-description">{entry.description}</p>
                            ) : (
                              <p className="footer-note">{t.reasonNotProvided}</p>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </main>
  );
}
