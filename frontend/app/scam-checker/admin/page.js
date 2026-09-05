"use client";

import { useEffect, useState } from "react";
import { getAuth, authHeader } from "../../../lib/auth";
import { parseApiError } from "../../../lib/apiError";
import BackLink from "../../BackLink";
import { T, LangToggle, readStoredLang, storeLang } from "../i18n";

const API_URL =
  process.env.NEXT_PUBLIC_SCAM_CHECKER_URL || "http://localhost:8002";

function EntryEvidence({ entryId, t }) {
  const [evidence, setEvidence] = useState(null);

  useEffect(() => {
    fetch(`${API_URL}/scam/admin/entries/${entryId}/evidence`, {
      headers: { ...authHeader() },
    })
      .then((r) => r.json())
      .then((body) => setEvidence(body.success ? body.data : []))
      .catch(() => setEvidence([]));
  }, [entryId]);

  async function download(evidenceId, filename) {
    const response = await fetch(`${API_URL}/scam/evidence/${evidenceId}/download`, {
      headers: { ...authHeader() },
    });
    if (!response.ok) return;
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
  }

  if (evidence === null) return <p className="footer-note">{t.adminLoadingEvidence}</p>;
  if (evidence.length === 0) return <p className="footer-note">{t.adminNoEvidence}</p>;

  return (
    <ul className="evidence-file-list">
      {evidence.map((e) => (
        <li key={e.id}>
          <button
            type="button"
            className="evidence-download-link"
            onClick={() => download(e.id, e.filename)}
          >
            {e.filename} ({Math.round(e.size_bytes / 1024)} Ko)
          </button>
        </li>
      ))}
    </ul>
  );
}

function EntryDetail({ entry, onResolved, t }) {
  const [reason, setReason] = useState("");
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);

  async function decide(endpoint, successMessage) {
    if (!reason.trim()) {
      setError(t.adminReasonRequired);
      return;
    }
    setError(null);
    const response = await fetch(`${API_URL}/scam/admin/${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeader() },
      body: JSON.stringify({ type: entry.type, value: entry.value, reason }),
    });
    const body = await response.json();
    if (!response.ok || !body.success) {
      setError(parseApiError(body, t.adminActionFailedFallback));
      return;
    }
    setStatus(successMessage);
    onResolved?.();
  }

  return (
    <div>
      {entry.description && <p className="blacklist-entry-description">{entry.description}</p>}

      <EntryEvidence entryId={entry.id} t={t} />

      {!status && (
        <div className="report-section" style={{ marginTop: 14 }}>
          <label>{t.adminDecisionReasonLabel}</label>
          <input type="text" value={reason} onChange={(e) => setReason(e.target.value)} onClick={(e) => e.stopPropagation()} />
          <div className="row" style={{ marginTop: 10 }}>
            {entry.status === "pending" && (
              <button type="button" className="primary" onClick={() => decide("confirm", t.adminConfirmedSuccess)}>
                {t.adminConfirmButton}
              </button>
            )}
            <button type="button" className="primary" onClick={() => decide("reject", t.adminRejectedSuccess)}>
              {t.adminRejectButton}
            </button>
          </div>
          {error && <div className="error-banner">{error}</div>}
        </div>
      )}
      {status && <p className="report-success">{status}</p>}
    </div>
  );
}

function EntryRow({ entry, expanded, onToggle, onResolved, t }) {
  const typeLabels = { phone: t.typePhone, url: t.typeUrl, domain: t.typeDomain };
  const locale = t === T.fr ? "fr-FR" : "en-US";

  return (
    <>
      <tr className="entry-row" onClick={onToggle} aria-expanded={expanded}>
        <td>{typeLabels[entry.type]}</td>
        <td><strong>{entry.value}</strong></td>
        <td>{t.statusLabels[entry.status]}</td>
        <td>
          {entry.report_count}
          {entry.coordinated_pattern_suspected && (
            <span className="entry-burst-flag" title={t.adminBurstTitle(entry.report_count, entry.report_spread_minutes)}>
              {t.adminBurstBadge}
            </span>
          )}
          {entry.low_diversity_suspected && (
            <span className="entry-burst-flag" title={t.adminLowDiversityTitle(entry.distinct_ip_count)}>
              {t.adminLowDiversityBadge}
            </span>
          )}
        </td>
        <td className="entry-reason-cell">{entry.admin_reason || t.reasonNotProvided}</td>
        <td>{new Date(entry.updated_at).toLocaleString(locale)}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} className="entry-detail-cell">
            <EntryDetail entry={entry} onResolved={onResolved} t={t} />
          </td>
        </tr>
      )}
    </>
  );
}

export default function AdminPage() {
  const [auth, setAuth] = useState(null);
  const [statusFilter, setStatusFilter] = useState("pending");
  const [sort, setSort] = useState("reports");
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [lang, setLang] = useState("fr");
  const t = T[lang];

  const [manualType, setManualType] = useState("phone");
  const [manualValue, setManualValue] = useState("");
  const [manualReason, setManualReason] = useState("");
  const [manualDescription, setManualDescription] = useState("");
  const [manualStatus, setManualStatus] = useState(null);
  const [manualError, setManualError] = useState(null);

  function loadEntries() {
    const params = new URLSearchParams({ sort });
    if (statusFilter) params.set("status", statusFilter);
    fetch(`${API_URL}/scam/admin/entries?${params}`, { headers: { ...authHeader() } })
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok || !body.success) {
          setError(parseApiError(body, t.adminLoadEntriesError));
          return;
        }
        setEntries(body.data);
      })
      .catch(() => setError(t.serviceUnreachable));
  }

  useEffect(() => {
    setAuth(getAuth());
    setLang(readStoredLang());
  }, []);

  useEffect(() => {
    if (auth?.user?.role === "admin") loadEntries();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auth, statusFilter, sort, lang]);

  function changeLang(next) {
    setLang(next);
    storeLang(next);
  }

  async function handleManualAdd(event) {
    event.preventDefault();
    setManualStatus(null);
    setManualError(null);
    const response = await fetch(`${API_URL}/scam/admin/blacklist`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeader() },
      body: JSON.stringify({
        type: manualType,
        value: manualValue.trim(),
        reason: manualReason.trim(),
        description: manualDescription.trim() || null,
      }),
    });
    const body = await response.json();
    if (!response.ok || !body.success) {
      setManualError(parseApiError(body, t.adminAddFailedFallback));
      return;
    }
    setManualStatus(t.adminAddedSuccess);
    setManualValue("");
    setManualReason("");
    setManualDescription("");
    loadEntries();
  }

  if (!auth) return null;

  if (auth.user?.role !== "admin") {
    return (
      <main className="main">
        <BackLink href="/scam-checker" label={t.backToScamChecker} />
        <div className="card">
          <p>{auth.user ? t.adminRestricted : t.adminLoginPrompt}</p>
          {auth.user && (
            <p className="footer-note">{t.adminConnectedAs(auth.user.email, auth.user.role)}</p>
          )}
        </div>
      </main>
    );
  }

  return (
    <main className="main">
      <BackLink href="/scam-checker" label={t.backToScamChecker} />

      <section className="hero">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <h1 style={{ margin: 0 }}>{t.adminTitle}</h1>
          <LangToggle lang={lang} onChange={changeLang} />
        </div>
        <p>{t.adminSubtitle}</p>
      </section>

      <form className="card" onSubmit={handleManualAdd}>
        <strong>{t.adminManualAddTitle}</strong>
        <div className="row" style={{ marginTop: 10 }}>
          <select value={manualType} onChange={(e) => setManualType(e.target.value)}>
            <option value="phone">{t.typePhone}</option>
            <option value="url">{t.typeUrl}</option>
            <option value="domain">{t.typeDomain}</option>
          </select>
          <input
            type="text"
            value={manualValue}
            onChange={(e) => setManualValue(e.target.value)}
            placeholder={t.adminValuePlaceholder}
            required
          />
        </div>
        <label>{t.adminReasonLabel}</label>
        <input type="text" value={manualReason} onChange={(e) => setManualReason(e.target.value)} required />
        <label>{t.adminModeOperatoireLabel}</label>
        <textarea
          value={manualDescription}
          onChange={(e) => setManualDescription(e.target.value)}
          style={{ minHeight: 70 }}
        />
        <button type="submit" className="primary">
          {t.adminAddButton}
        </button>
        {manualStatus && <p className="report-success">{manualStatus}</p>}
        {manualError && <div className="error-banner">{manualError}</div>}
      </form>

      <div className="card" style={{ marginBottom: 20 }}>
        <strong>{t.adminEntriesTitle}</strong>
        <div className="row" style={{ marginTop: 10, marginBottom: 4 }}>
          {["pending", "confirmed", ""].map((s) => (
            <button
              key={s || "all"}
              type="button"
              className="primary"
              style={{
                marginTop: 0,
                background: statusFilter === s ? undefined : "var(--border)",
                color: statusFilter === s ? undefined : "var(--text)",
              }}
              onClick={() => setStatusFilter(s)}
            >
              {t.statusLabels[s]}
            </button>
          ))}
        </div>
        <label style={{ display: "block", marginTop: 12 }}>{t.adminSortByLabel}</label>
        <div className="row" style={{ marginTop: 6, marginBottom: 4 }}>
          {[
            { key: "reports", label: t.adminSortReports },
            { key: "recent", label: t.adminSortRecent },
          ].map(({ key, label }) => (
            <button
              key={key}
              type="button"
              className="primary"
              style={{
                marginTop: 0,
                background: sort === key ? undefined : "var(--border)",
                color: sort === key ? undefined : "var(--text)",
              }}
              onClick={() => setSort(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {entries && entries.length === 0 && (
        <div className="card">
          <p>{t.adminNoEntries}</p>
        </div>
      )}

      {entries && entries.length > 0 && (
        <>
          <p className="entry-expand-hint">{t.expandHint}</p>
          <div className="entries-table-wrap">
            <table className="entries-table">
              <thead>
                <tr>
                  <th>{t.colType}</th>
                  <th>{t.colValue}</th>
                  <th>{t.colStatus}</th>
                  <th>{t.colReports}</th>
                  <th>{t.colReason}</th>
                  <th>{t.colUpdated}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <EntryRow
                    key={entry.id}
                    entry={entry}
                    expanded={expandedId === entry.id}
                    onToggle={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                    onResolved={loadEntries}
                    t={t}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </main>
  );
}
