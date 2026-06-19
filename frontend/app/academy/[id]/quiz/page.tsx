'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, CheckCircle, XCircle, Award, ShieldCheck } from 'lucide-react';
import { fetchModule, submitQuiz } from '@/lib/api';
import type { ModuleDetail, QuizResult } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';

export default function QuizPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { user, token } = useAuth();
  const [module, setModule] = useState<ModuleDetail | null>(null);
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const [submitted, setSubmitted] = useState(false);
  const [result, setResult] = useState<QuizResult | null>(null);
  const [loading, setLoading] = useState(true);

  // URL de base de votre API (ex: http://localhost:5000 ou https://monsite.com)
  const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || '';

  useEffect(() => {
    if (id) {
      fetchModule(Number(id))
        .then(data => setModule(data))
        .catch(console.error)
        .finally(() => setLoading(false));
    }
  }, [id]);

  const handleChange = (questionId: number, choiceId: number) => {
    setAnswers(prev => ({ ...prev, [questionId]: choiceId }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user || !token) {
      alert('Veuillez vous connecter pour soumettre le quiz.');
      router.push('/login');
      return;
    }
    try {
      const resultData = await submitQuiz(Number(id), answers, token);
      setResult(resultData);
      setSubmitted(true);
    } catch (error: any) {
      alert(error.message);
    }
  };

  if (loading) return <div className="p-12 text-center text-gray-500 font-medium">Chargement du quiz...</div>;
  if (!module) return <div className="p-12 text-center text-red-500 font-medium">Module non trouvé.</div>;

  // --- FAÇADE DE RÉSULTATS (APRÈS SOUMISSION) ---
  if (submitted && result) {
    return (
      <div className="max-w-3xl mx-auto px-6 py-12 space-y-8 bg-white rounded-2xl shadow-sm border border-gray-100">
        <h2 className="text-2xl font-bold flex items-center gap-2 text-dark-blue">
          <Award className="w-6 h-6 text-cyber-blue" /> Résultat du quiz
        </h2>
        
        <div className="text-center py-6 bg-gray-50 rounded-2xl space-y-3">
          <p className="text-5xl font-extrabold text-cyber-blue">
            {result.score} / {result.total}
          </p>
          <p className={`text-lg font-bold ${result.passed ? 'text-green-600' : 'text-red-600'}`}>
            {result.passed ? (
              <span className="flex items-center justify-center gap-2"><CheckCircle className="w-5 h-5" /> Félicitations, vous avez réussi !</span>
            ) : (
              <span className="flex items-center justify-center gap-2"><XCircle className="w-5 h-5" /> Vous pouvez réessayer.</span>
            )}
          </p>
          <p className="text-sm text-gray-600 max-w-md mx-auto">{result.message}</p>
          
          <button
            onClick={() => router.push(`/academy/${id}`)}
            className="mt-4 bg-cyber-blue hover:bg-blue-700 text-white px-6 py-2.5 rounded-xl font-semibold transition flex items-center justify-center gap-2 mx-auto shadow-sm"
          >
            <ArrowLeft className="w-4 h-4" /> Revenir au module
          </button>
        </div>

        <div className="space-y-4 pt-4 border-t border-gray-100">
          <h3 className="text-base font-bold text-dark-blue">Détail des réponses :</h3>
          <div className="space-y-3">
            {result.details.map((d, idx) => {
              const question = module.questions.find(q => q.id === d.question_id);
              return (
                <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl border border-gray-100 bg-white">
                  <div className="flex items-center gap-3">
                    <span className="font-semibold text-gray-700 text-sm">Question {idx + 1} :</span>
                    <span className={d.is_correct ? 'text-green-600' : 'text-red-600'}>
                      {d.is_correct ? (
                        <span className="flex items-center gap-1 text-xs font-bold bg-green-50 px-2 py-1 rounded-lg"><CheckCircle className="w-4 h-4" /> Correct</span>
                      ) : (
                        <span className="flex items-center gap-1 text-xs font-bold bg-red-50 px-2 py-1 rounded-lg"><XCircle className="w-4 h-4" /> Incorrect</span>
                      )}
                    </span>
                  </div>

                  {/* Aperçu de l'image dans le récapitulatif si elle existe */}
                  {question?.image && (
                    <div className="shrink-0 border border-gray-200 rounded-lg overflow-hidden bg-gray-50">
                      <img
                        src={`${API_BASE_URL}${question.image}`}
                        alt=""
                        className="w-16 h-12 object-cover"
                        onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  // --- FORMULAIRE DU QUIZ (EN COURS) ---
  return (
    <div className="max-w-3xl mx-auto px-6 py-12 bg-white rounded-2xl shadow-sm border border-gray-100 space-y-6">
      <button onClick={() => router.back()} className="text-cyber-blue hover:text-blue-700 text-sm font-semibold flex items-center gap-1 transition">
        <ArrowLeft className="w-4 h-4" /> Retour
      </button>
      
      <div className="border-b border-gray-100 pb-4">
        <h1 className="text-2xl font-bold flex items-center gap-2 text-dark-blue">
          <ShieldCheck className="w-7 h-7 text-cyber-blue" /> Quiz : {module.title}
        </h1>
        <p className="text-sm text-gray-500 mt-1">Répondez aux {module.questions.length} questions ci-dessous.</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-8">
        {module.questions.map((q, idx) => (
          <div key={q.id} className="p-5 rounded-2xl border border-gray-100 bg-gray-50/50 space-y-4">
            <p className="font-bold text-dark-blue text-base">
              <span className="text-cyber-blue mr-1">{idx + 1}.</span> {q.text}
            </p>
            
            {/* RÉSOLUTION IMAGE : Conteneur responsive, centré et de hauteur maximum contrôlée */}
            {q.image && (
              <div className="w-full flex justify-center bg-white border border-gray-100 rounded-xl p-2 overflow-hidden shadow-2xs">
                <img
                  src={`${API_BASE_URL}${q.image}`}
                  alt="Illustration de la question"
                  className="max-w-full rounded-lg max-h-64 object-contain"
                  // Sécurité : masque l'image cassée si le lien de la BD est introuvable
                  onError={(e) => { (e.target as HTMLImageElement).parentElement!.style.display = 'none'; }}
                />
              </div>
            )}

            {/* Liste des choix de réponses bien espacée */}
            <div className="space-y-2 pt-2">
              {q.choices.map((choice) => (
                <label 
                  key={choice.id} 
                  className={`flex items-center gap-3 cursor-pointer bg-white border border-gray-200 hover:border-cyber-blue/50 hover:bg-blue-50/20 p-3.5 rounded-xl transition-all ${
                    answers[q.id] === choice.id ? 'border-cyber-blue bg-blue-50/10 ring-1 ring-cyber-blue' : ''
                  }`}
                >
                  <input
                    type="radio"
                    name={`question-${q.id}`}
                    value={choice.id}
                    onChange={() => handleChange(q.id, choice.id)}
                    checked={answers[q.id] === choice.id}
                    required
                    className="w-4 h-4 text-cyber-blue focus:ring-cyber-blue border-gray-300"
                  />
                  <span className="text-sm font-medium text-gray-700">{choice.text}</span>
                </label>
              ))}
            </div>
          </div>
        ))}

        <button
          type="submit"
          className="w-full bg-cyber-blue hover:bg-blue-700 text-white font-bold py-4 rounded-xl transition shadow-md flex items-center justify-center gap-2 text-sm tracking-wide"
        >
          <Award className="w-5 h-5" /> Soumettre mes réponses
        </button>
      </form>
    </div>
  );
}
