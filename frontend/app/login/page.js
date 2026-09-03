"use client";

import { useState } from "react";
import { saveAuth } from "../../lib/auth";
import { parseApiError } from "../../lib/apiError";
import PasswordInput from "../PasswordInput";
import BackLink from "../BackLink";

const API_URL = process.env.NEXT_PUBLIC_AUTH_URL || "http://localhost:8001";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const body = await response.json();
      if (!response.ok || !body.success) {
        setError(parseApiError(body, "Connexion impossible."));
        return;
      }
      saveAuth({
        access_token: body.data.access_token,
        refresh_token: body.data.refresh_token,
        user: body.data.user,
      });
      // Un compte admin est envoyé directement sur le back-office — sinon
      // il faudrait remarquer soi-même le petit lien "Admin" dans le menu.
      window.location.href =
        body.data.user.role === "admin" ? "/scam-checker/admin" : "/scam-checker";
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
        <h1>Connexion</h1>
        <p>Connecte-toi pour pouvoir signaler une entrée suspecte au Scam Checker.</p>
      </section>

      <form className="card" onSubmit={handleSubmit}>
        <label>Email</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <label>Mot de passe</label>
        <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} required />
        <button type="submit" className="primary" disabled={loading}>
          {loading ? "Connexion..." : "Se connecter"}
        </button>
      </form>

      {error && <div className="error-banner">{error}</div>}

      <p className="footer-note">
        Pas encore de compte ? <a href="/register">S&apos;inscrire</a>
      </p>
    </main>
  );
}
