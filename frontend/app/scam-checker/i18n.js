"use client";

// Traduction FR/EN partagée par les 3 pages du module Scam-Checker
// (/scam-checker, /scam-checker/liste, /scam-checker/admin) — demande du
// 28/08/2026 d'étendre la sélection de langue au-delà du seul verdict
// retourné par l'API. Le reste du site (accueil, connexion, inscription)
// n'est volontairement pas concerné par ce fichier.
//
// La préférence est mémorisée dans localStorage sous une clé commune, pour
// qu'un choix fait sur une page reste appliqué en naviguant vers une autre
// page du module.

export const LANG_STORAGE_KEY = "cybersafe_scam_lang";

export const T = {
  fr: {
    langGroupLabel: "Langue",
    backToScamChecker: "Retour au Scam-Checker",
    backToHome: "Retour à l'accueil",
    loginLink: "Connecte-toi",
    typePhone: "Téléphone",
    typeUrl: "URL",
    typeDomain: "Domaine",
    serviceUnreachable: "Impossible de contacter le service (port 8002).",

    // /scam-checker
    checkTitle: "Scam-Checker",
    checkSubtitle:
      "Collez un message suspect (SMS, email, WhatsApp) ou un lien reçu. Le " +
      "système vous indique en quelques secondes s'il s'agit probablement " +
      "d'une arnaque.",
    checkLangNote: "Le résultat s'affiche dans la langue choisie ici.",
    checkPlaceholder:
      "Exemple : « Félicitations ! Vous avez gagné 500 000 FCFA. Contactez " +
      "le 678901234 pour retirer votre gain. »",
    checkButton: "Vérifier",
    checkButtonLoading: "Analyse en cours...",
    checkErrorFallback:
      "Le message soumis n'a pas pu être analysé (vérifiez qu'il n'est pas vide).",
    checkNetworkError:
      "Impossible de contacter le service de vérification. Vérifiez qu'il " +
      "est bien démarré (port 8002).",
    scoreLabel: "Score",
    motifsHeading: "Motifs détectés",
    conseilsHeading: "Conseils",
    consultTitle: "Consulter la liste noire",
    consultDesc: "Numéros, liens et domaines déjà confirmés frauduleux par un administrateur.",
    consultButton: "📋 Voir la liste noire confirmée",
    reportSectionTitle: "Signaler un numéro, un lien ou un domaine comme arnaque",
    viewConfirmedLink: "📋 Voir les signalements déjà confirmés",
    valueToReportPlaceholder: "Valeur à signaler",
    modeOperatoireLabel: "Mode opératoire (comment ça s'est passé, optionnel)",
    modeOperatoirePlaceholder:
      "Décrivez le déroulement de l'arnaque : ce qui vous a été dit, demandé, promis...",
    evidenceLabel: "Preuves (captures d'écran, PDF — jusqu'à 5 fichiers, 5 Mo chacun)",
    evidenceRejected: (file) =>
      `« ${file} » n'est pas un type accepté (image PNG/JPEG/WebP ou PDF).`,
    reportButton: "Signaler",
    reportButtonSending: "Envoi...",
    reportErrorFallback: "Le signalement a échoué.",
    reportSuccess: (count) =>
      `Signalement enregistré (${count} signalement(s) reçu(s)) — en attente de vérification par un administrateur.`,
    evidenceAttachedOk: (n) => ` ${n} preuve(s) jointe(s).`,
    evidenceAttachedPartial: (ok, total, fail) =>
      ` ${ok}/${total} preuve(s) jointe(s) (${fail} échec(s)).`,
    loginPromptSuffix:
      "pour signaler une entrée comme arnaque et contribuer à la liste noire communautaire.",
    footerVigilance:
      "Cette vérification ne remplace pas votre vigilance. En cas de doute, " +
      "ne répondez pas et contactez directement l'organisme concerné.",
    footerMobileMoney:
      "⚠️ Cet outil analyse des messages et des liens : il ne couvre pas les " +
      "arnaques mobile money commises en personne (faux agents en agence). " +
      "Vérifiez toujours l'identité d'un agent et ne partagez jamais votre " +
      "code secret, même en agence.",
    verdictLabels: { ROUGE: "Arnaque probable", ORANGE: "Suspect", VERT: "Légitime" },

    // /scam-checker/liste
    listeTitle: "Signalements confirmés",
    listeSubtitle:
      "Numéros, liens et domaines signalés par la communauté puis vérifiés et " +
      "confirmés par un administrateur, avec le mode opératoire rapporté " +
      "quand il est disponible.",
    listeLoginPromptSuffix: "pour consulter la liste des signalements confirmés.",
    listeLoadError: "Impossible de charger la liste.",
    listeEmpty: "Aucune entrée confirmée pour le moment.",
    listeReportCount: (n) => `${n} signalement${n > 1 ? "s" : ""}`,

    // /scam-checker/admin
    adminRestricted: "Cette page est réservée aux administrateurs.",
    adminLoginPrompt: "Connecte-toi avec un compte administrateur pour accéder à cette page.",
    adminConnectedAs: (email, role) => `Connecté en tant que ${email} — rôle détecté : «${role}»`,
    adminTitle: "Back-office administrateur",
    adminSubtitle:
      "Confirmer ou rejeter les signalements en attente, ajouter une entrée " +
      "directement, consulter les preuves.",
    adminManualAddTitle: "Ajout manuel en liste noire",
    adminValuePlaceholder: "Valeur",
    adminReasonLabel: "Motif (obligatoire)",
    adminModeOperatoireLabel: "Mode opératoire (optionnel)",
    adminAddButton: "Ajouter et confirmer",
    adminAddedSuccess: "Entrée ajoutée et confirmée.",
    adminAddFailedFallback: "L'ajout a échoué.",
    adminEntriesTitle: "Entrées à traiter",
    colType: "Type",
    colValue: "Valeur",
    colStatus: "Statut",
    colReports: "Signalements",
    colReason: "Motif admin",
    colUpdated: "Mise à jour",
    reasonNotProvided: "—",
    expandHint: "Cliquer sur une ligne pour voir les détails",
    statusLabels: { pending: "En attente", confirmed: "Confirmée", "": "Toutes" },
    adminSortByLabel: "Trier par",
    adminSortReports: "Nb. signalements (priorité)",
    adminSortRecent: "Dernière modification",
    adminNoEntries: "Aucune entrée pour ce filtre.",
    adminLoadEntriesError: "Impossible de charger les entrées.",
    adminHideEvidence: "▲ Masquer les preuves",
    adminShowEvidence: "▼ Voir les preuves",
    adminLoadingEvidence: "Chargement des preuves...",
    adminNoEvidence: "Aucune preuve jointe.",
    adminDecisionReasonLabel: "Motif de la décision",
    adminConfirmButton: "Confirmer (liste noire)",
    adminRejectButton: "Rejeter / retirer",
    adminReasonRequired: "Le motif est obligatoire.",
    adminActionFailedFallback: "L'action a échoué.",
    adminConfirmedSuccess: "Entrée confirmée.",
    adminRejectedSuccess: "Entrée rejetée / retirée.",
    adminBurstBadge: "⚠️ rafale suspecte",
    adminBurstTitle: (count, minutes) =>
      `${count} signalements en moins de ${minutes} min — possible coordination, à examiner avec prudence.`,
    adminLowDiversityBadge: "⚠️ même origine",
    adminLowDiversityTitle: () =>
      "Tous les signalements proviennent de la même adresse IP — possible manipulation par un seul acteur, à examiner avec prudence.",
  },

  en: {
    langGroupLabel: "Language",
    backToScamChecker: "Back to Scam-Checker",
    backToHome: "Back to home",
    loginLink: "Log in",
    typePhone: "Phone",
    typeUrl: "URL",
    typeDomain: "Domain",
    serviceUnreachable: "Could not reach the service (port 8002).",

    // /scam-checker
    checkTitle: "Scam-Checker",
    checkSubtitle:
      "Paste a suspicious message (SMS, email, WhatsApp) or a link you " +
      "received. The system tells you within seconds whether it's likely a scam.",
    checkLangNote: "The result is shown in the language selected here.",
    checkPlaceholder:
      "Example: “Congratulations! You have won 500,000 FCFA. Contact " +
      "678901234 to claim your prize.”",
    checkButton: "Check",
    checkButtonLoading: "Analyzing...",
    checkErrorFallback:
      "The submitted message could not be analyzed (make sure it isn't empty).",
    checkNetworkError:
      "Could not reach the verification service. Make sure it is running (port 8002).",
    scoreLabel: "Score",
    motifsHeading: "Detected motifs",
    conseilsHeading: "Advice",
    consultTitle: "Browse the blacklist",
    consultDesc: "Numbers, links, and domains already confirmed as fraudulent by an administrator.",
    consultButton: "📋 View the confirmed blacklist",
    reportSectionTitle: "Report a number, link, or domain as a scam",
    viewConfirmedLink: "📋 View confirmed reports",
    valueToReportPlaceholder: "Value to report",
    modeOperatoireLabel: "How it happened (optional)",
    modeOperatoirePlaceholder:
      "Describe how the scam unfolded: what you were told, asked, or promised...",
    evidenceLabel: "Evidence (screenshots, PDF — up to 5 files, 5 MB each)",
    evidenceRejected: (file) =>
      `"${file}" is not an accepted file type (PNG/JPEG/WebP image or PDF).`,
    reportButton: "Report",
    reportButtonSending: "Sending...",
    reportErrorFallback: "The report failed.",
    reportSuccess: (count) =>
      `Report recorded (${count} report(s) received) — awaiting review by an administrator.`,
    evidenceAttachedOk: (n) => ` ${n} piece(s) of evidence attached.`,
    evidenceAttachedPartial: (ok, total, fail) =>
      ` ${ok}/${total} piece(s) of evidence attached (${fail} failed).`,
    loginPromptSuffix: "to report an entry as a scam and contribute to the community blacklist.",
    footerVigilance:
      "This check does not replace your own vigilance. When in doubt, do " +
      "not reply and contact the organization directly.",
    footerMobileMoney:
      "⚠️ This tool analyzes messages and links: it does not cover " +
      "in-person mobile money scams (fake agents at agencies). Always " +
      "verify an agent's identity and never share your secret code, even at an agency.",
    verdictLabels: { ROUGE: "Likely scam", ORANGE: "Suspicious", VERT: "Legitimate" },

    // /scam-checker/liste
    listeTitle: "Confirmed reports",
    listeSubtitle:
      "Numbers, links, and domains reported by the community, then verified " +
      "and confirmed by an administrator, with the reported method when available.",
    listeLoginPromptSuffix: "to view the list of confirmed reports.",
    listeLoadError: "Could not load the list.",
    listeEmpty: "No confirmed entries yet.",
    listeReportCount: (n) => `${n} report${n > 1 ? "s" : ""}`,

    // /scam-checker/admin
    adminRestricted: "This page is restricted to administrators.",
    adminLoginPrompt: "Log in with an administrator account to access this page.",
    adminConnectedAs: (email, role) => `Logged in as ${email} — detected role: "${role}"`,
    adminTitle: "Administrator back-office",
    adminSubtitle: "Confirm or reject pending reports, add an entry directly, review evidence.",
    adminManualAddTitle: "Manually add to blacklist",
    adminValuePlaceholder: "Value",
    adminReasonLabel: "Reason (required)",
    adminModeOperatoireLabel: "Method (optional)",
    adminAddButton: "Add and confirm",
    adminAddedSuccess: "Entry added and confirmed.",
    adminAddFailedFallback: "The addition failed.",
    adminEntriesTitle: "Entries to review",
    colType: "Type",
    colValue: "Value",
    colStatus: "Status",
    colReports: "Reports",
    colReason: "Admin reason",
    colUpdated: "Updated",
    reasonNotProvided: "—",
    expandHint: "Click a row to view details",
    statusLabels: { pending: "Pending", confirmed: "Confirmed", "": "All" },
    adminSortByLabel: "Sort by",
    adminSortReports: "Number of reports (priority)",
    adminSortRecent: "Last updated",
    adminNoEntries: "No entries for this filter.",
    adminLoadEntriesError: "Could not load entries.",
    adminHideEvidence: "▲ Hide evidence",
    adminShowEvidence: "▼ View evidence",
    adminLoadingEvidence: "Loading evidence...",
    adminNoEvidence: "No evidence attached.",
    adminDecisionReasonLabel: "Reason for the decision",
    adminConfirmButton: "Confirm (blacklist)",
    adminRejectButton: "Reject / remove",
    adminReasonRequired: "A reason is required.",
    adminActionFailedFallback: "The action failed.",
    adminConfirmedSuccess: "Entry confirmed.",
    adminRejectedSuccess: "Entry rejected / removed.",
    adminBurstBadge: "⚠️ suspicious burst",
    adminBurstTitle: (count, minutes) =>
      `${count} reports in under ${minutes} min — possible coordination, review with caution.`,
    adminLowDiversityBadge: "⚠️ same origin",
    adminLowDiversityTitle: () =>
      "All reports come from the same IP address — possible manipulation by a single actor, review with caution.",
  },
};

export function readStoredLang() {
  try {
    const saved = window.localStorage.getItem(LANG_STORAGE_KEY);
    return saved === "fr" || saved === "en" ? saved : "fr";
  } catch {
    return "fr";
  }
}

export function storeLang(lang) {
  try {
    window.localStorage.setItem(LANG_STORAGE_KEY, lang);
  } catch {
    // Pas grave si la préférence ne peut pas être mémorisée (navigation privée...).
  }
}

export function LangToggle({ lang, onChange }) {
  return (
    <div className="row" style={{ gap: 6 }} role="group" aria-label={T[lang].langGroupLabel}>
      {["fr", "en"].map((l) => (
        <button
          key={l}
          type="button"
          className="primary"
          style={{
            marginTop: 0,
            padding: "4px 12px",
            background: lang === l ? undefined : "var(--border)",
            color: lang === l ? undefined : "var(--text)",
          }}
          onClick={() => onChange(l)}
          aria-pressed={lang === l}
        >
          {l.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
