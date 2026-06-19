// lib/api.ts

// 1. URL de base du backend pour l'API
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api';

// 2. Racine du serveur pour reconstruire les liens des images et médias (sans le suffixe /api)
export const MEDIA_URL = API_URL.replace(/\/api$/, '');

export interface ModuleSummary {
  id: number;
  title: string;
  description: string;
  order: number;
  question_count: number;
  video_url: string | null;
  video_file: string | null;   
  pdf_file: string | null;
  image: string | null;
}

export interface Choice {
  id: number;
  text: string;
  is_correct: boolean;
}

export interface Question {
  id: number;
  text: string;
  choices: Choice[];
  image?: string | null; // Correctement typé pour la BD
}

// CORRECTION : Nettoyage du doublon 'image', hérité directement de ModuleSummary
export interface ModuleDetail extends ModuleSummary {
  content: string;
  questions: Question[];
}

export interface QuizResult {
  score: number;
  total: number;
  passed: boolean;
  details: {
    question_id: number;
    selected_choice_id: number;
    is_correct: boolean;
  }[];
  message: string;
}

// === ACADEMY API ===
export const fetchModules = async (token?: string): Promise<ModuleSummary[]> => {
  const url = `${API_URL}/academy/modules/`;
  const headers: HeadersInit = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Erreur ${res.status}: ${text}`);
    }
    return res.json();
  } catch (error) {
    console.error('fetchModules error:', error);
    throw error;
  }
};

// AMÉLIORATION : Ajout du token optionnel pour fetchModule si votre backend filtre les contenus par utilisateur
export const fetchModule = async (id: number, token?: string): Promise<ModuleDetail> => {
  const url = `${API_URL}/academy/modules/${id}/`;
  const headers: HeadersInit = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error('Module non trouvé');
  return res.json();
};

export const submitQuiz = async (
  moduleId: number,
  answers: Record<number, number>,
  token: string
): Promise<QuizResult> => {
  const url = `${API_URL}/academy/quiz/submit/`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ module_id: moduleId, answers }),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Erreur inconnue' }));
    throw new Error(error.error || 'Erreur lors de la soumission');
  }
  return res.json();
};

export const fetchProgress = async (token: string): Promise<number[]> => {
  const res = await fetch(`${API_URL}/academy/progress/`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Erreur lors du chargement de la progression');
  const data = await res.json();
  return data.completed;
};

// === AUTH API ===
export const loginUser = async (email: string, password: string) => {
  const url = `${API_URL}/auth/login/`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || 'Erreur de connexion');
  }
  return res.json();
};

export const registerUser = async (userData: any) => {
  const url = `${API_URL}/auth/register/`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userData),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || "Erreur d'inscription");
  }
  return res.json();
};

export const fetchProfile = async (token: string) => {
  const url = `${API_URL}/auth/profile/`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Erreur lors du chargement du profil');
  return res.json();
};
