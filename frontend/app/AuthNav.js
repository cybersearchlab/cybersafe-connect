"use client";

import { useEffect, useState } from "react";
import { getAuth, clearAuth } from "../lib/auth";

export default function AuthNav() {
  const [auth, setAuth] = useState(null);

  useEffect(() => {
    setAuth(getAuth());
    const onChange = () => setAuth(getAuth());
    window.addEventListener("cybersafe-auth-changed", onChange);
    window.addEventListener("storage", onChange);
    return () => {
      window.removeEventListener("cybersafe-auth-changed", onChange);
      window.removeEventListener("storage", onChange);
    };
  }, []);

  if (auth?.user) {
    return (
      <div className="nav-user">
        {auth.user.role === "admin" && (
          <a href="/scam-checker/admin" className="admin-badge">
            🛠️ Back-office admin
          </a>
        )}
        <span>{auth.user.fullname}</span>
        <button
          type="button"
          onClick={() => {
            clearAuth();
            window.location.href = "/";
          }}
        >
          Déconnexion
        </button>
      </div>
    );
  }

  return (
    <div className="nav-user">
      <a href="/login">Connexion</a>
      <a href="/register">Inscription</a>
    </div>
  );
}
