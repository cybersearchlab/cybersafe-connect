"use client";

// Petite couche d'accès à l'état de connexion, stocké côté client dans
// localStorage. Le frontend ne fait confiance à aucune information qu'il
// stocke lui-même pour autoriser une action : c'est toujours le backend
// (auth via le token JWT, scam-checker via security.py) qui décide.

const STORAGE_KEY = "cybersafe_auth";

export function saveAuth(data) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  window.dispatchEvent(new Event("cybersafe-auth-changed"));
}

export function getAuth() {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function clearAuth() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(STORAGE_KEY);
  window.dispatchEvent(new Event("cybersafe-auth-changed"));
}

export function authHeader() {
  const auth = getAuth();
  if (!auth?.access_token) return {};
  return { Authorization: `Bearer ${auth.access_token}` };
}
