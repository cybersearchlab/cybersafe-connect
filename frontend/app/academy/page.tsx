'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { BookOpen, Video, FileText, ShieldCheck } from 'lucide-react';
import { fetchModules } from '@/lib/api';
import type { ModuleSummary } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';

export default function AcademyList() {
  const { token } = useAuth();
  const [modules, setModules] = useState<ModuleSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchModules(token ?? undefined)
      .then(data => setModules(data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) {
    return <div className="p-8 text-center text-gray-500">Chargement des modules...</div>;
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-3xl font-bold text-dark-blue mb-6 flex items-center gap-2">
        <ShieldCheck className="w-8 h-8 text-cyber-blue" />
        CyberSafe Academy
      </h1>
      <p className="text-gray-600 mb-8">
        Apprenez à vous protéger avec nos modules de formation adaptés à votre profil.
      </p>
      <div className="grid md:grid-cols-2 gap-6">
        {modules.map((mod) => (
          <Link key={mod.id} href={`/academy/${mod.id}`} className="block">
            <div className="bg-white rounded-xl shadow hover:shadow-lg transition-shadow border border-gray-100 overflow-hidden h-full flex flex-col">
              {/* === IMAGE DE COUVERTURE === */}
              {mod.image && (
                <div className="w-full h-40 overflow-hidden">
                  <img
                    src={`${process.env.NEXT_PUBLIC_API_URL}${mod.image}`}
                    alt={mod.title}
                    className="w-full h-full object-cover hover:scale-105 transition-transform duration-300"
                  />
                </div>
              )}
              <div className="p-6 flex flex-col flex-1">
                <h2 className="text-xl font-semibold text-dark-blue">{mod.title}</h2>
                <p className="text-gray-600 mt-2 flex-1">{mod.description}</p>
                <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
                  <span>{mod.question_count} questions</span>
                  <div className="flex items-center gap-2">
                    {mod.video_url && <Video className="w-4 h-4 text-cyber-blue" />}
                    {mod.pdf_file && <FileText className="w-4 h-4 text-cyber-blue" />}
                    <span className="text-cyber-blue">→</span>
                  </div>
                </div>
              </div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}