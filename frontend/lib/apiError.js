// Normalise les différents formats d'erreur renvoyés par les services
// backend en un simple message texte, affichable directement en JSX.
//
// Trois formats possibles :
//   - Nos services (auth via son gestionnaire d'erreurs) :
//       { success: false, error: "...", code: "..." }
//   - scam-checker, pour les erreurs de validation Pydantic (422) :
//       { success: false, errors: { champ: ["message", ...] }, code: "..." }
//     (voir services/scam-checker/app.py, validation_exception_handler)
//   - FastAPI brut, pour toute erreur de validation NON interceptée par un
//     gestionnaire personnalisé (ex. module auth) :
//       { detail: [{ loc: [...], msg: "...", type: "..." }, ...] }
//     `detail` est alors un TABLEAU D'OBJETS, pas une chaîne — le rendre
//     directement dans du JSX (`{error}`) fait planter React avec
//     "Objects are not valid as a React child".
export function parseApiError(body, fallback = "Une erreur est survenue.") {
  if (!body) return fallback;

  if (typeof body.error === "string" && body.error) {
    return body.error;
  }

  if (body.errors && typeof body.errors === "object" && !Array.isArray(body.errors)) {
    const messages = Object.values(body.errors).flat().filter(Boolean);
    if (messages.length > 0) return messages.join(" ");
  }

  if (typeof body.detail === "string" && body.detail) {
    return body.detail;
  }

  if (Array.isArray(body.detail)) {
    const messages = body.detail
      .map((item) => (typeof item?.msg === "string" ? item.msg : null))
      .filter(Boolean);
    if (messages.length > 0) return messages.join(" ");
  }

  return fallback;
}
