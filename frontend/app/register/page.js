"use client";

import { useState } from "react";
import { parseApiError } from "../../lib/apiError";
import PasswordInput from "../PasswordInput";
import BackLink from "../BackLink";

const API_URL = process.env.NEXT_PUBLIC_AUTH_URL || "http://localhost:8001";

// Reflète exactement les règles imposées côté serveur (services/auth/schemas.py,
// RegisterRequest.validate_password) : au moins 8 caractères, une majuscule,
// une minuscule et un chiffre. Dupliqué ici volontairement pour donner un
// retour immédiat à l'utilisateur, sans attendre un aller-retour serveur.
const PASSWORD_RULES = [
  { key: "length", label: "Au moins 8 caractères", test: (v) => v.length >= 8 },
  { key: "upper", label: "Une majuscule", test: (v) => /[A-Z]/.test(v) },
  { key: "lower", label: "Une minuscule", test: (v) => /[a-z]/.test(v) },
  { key: "digit", label: "Un chiffre", test: (v) => /\d/.test(v) },
];

function passwordUnmetRules(password) {
  return PASSWORD_RULES.filter((rule) => !rule.test(password));
}

export default function RegisterPage() {
  const [step, setStep] = useState("form"); // "form" | "otp" | "done"
  const [fullname, setFullname] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("citizen");
  const [code, setCode] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleRegister(event) {
    event.preventDefault();
    setError(null);

    const unmet = passwordUnmetRules(password);
    if (unmet.length > 0) {
      setError(
        `Le mot de passe ne respecte pas tous les critères requis : ${unmet
          .map((r) => r.label.toLowerCase())
          .join(", ")}.`
      );
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fullname, email, password, role }),
      });
      const body = await response.json();
      if (!response.ok || !body.success) {
        setError(parseApiError(body, "L'inscription a échoué."));
        return;
      }
      setStep("otp");
    } catch {
      setError("Impossible de contacter le service d'authentification (port 8001).");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(event) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/auth/verify-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code }),
      });
      const body = await response.json();
      if (!response.ok || !body.success) {
        setError(parseApiError(body, "Code de vérification invalide."));
        return;
      }
      setStep("done");
    } catch {
      setError("Impossible de contacter le service d'authentification (port 8001).");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="main">
      <BackLink />

      <section className="hero">
        <h1>Créer un compte</h1>
        <p>Un compte permet de signaler une entrée suspecte au Scam Checker.</p>
      </section>

      {step === "form" && (
        <form className="card" onSubmit={handleRegister}>
          <label>Nom complet</label>
          <input
            type="text"
            value={fullname}
            onChange={(e) => setFullname(e.target.value)}
            required
          />
          <label>Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <label>Mot de passe</label>
          <PasswordInput
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
          />
          {password.length > 0 && (
            <ul className="password-rules">
              {PASSWORD_RULES.map((rule) => {
                const met = rule.test(password);
                return (
                  <li key={rule.key} className={met ? "met" : "unmet"}>
                    {met ? "✓" : "✗"} {rule.label}
                  </li>
                );
              })}
            </ul>
          )}
          <label>Rôle</label>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="citizen">Citoyen</option>
            <option value="company">Entreprise</option>
          </select>
          <button type="submit" className="primary" disabled={loading}>
            {loading ? "Envoi..." : "S'inscrire"}
          </button>
        </form>
      )}

      {step === "otp" && (
        <form className="card" onSubmit={handleVerify}>
          <p>
            Un code de vérification à 6 chiffres a été envoyé à <strong>{email}</strong>.
          </p>
          <label>Code de vérification</label>
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            maxLength={6}
            required
          />
          <button type="submit" className="primary" disabled={loading}>
            {loading ? "Vérification..." : "Vérifier"}
          </button>
        </form>
      )}

      {step === "done" && (
        <div className="card">
          <p>Compte vérifié avec succès.</p>
          <a href="/login">
            <button type="button" className="primary">
              Se connecter
            </button>
          </a>
        </div>
      )}

      {error && <div className="error-banner">{error}</div>}
    </main>
  );
}
