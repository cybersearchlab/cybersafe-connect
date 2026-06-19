'use client';
import { useAuth } from '@/context/AuthContext';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { TrendingUp, Bell, FileText, BookOpen, Shield, Settings, User, AlertTriangle } from 'lucide-react';
import { fetchProgress, fetchModules } from '@/lib/api';

export default function CompanyDashboard() {
  const { user, token } = useAuth();
  const [completedModules, setCompletedModules] = useState<number[]>([]);
  const [totalModules, setTotalModules] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      Promise.all([
        fetchProgress(token),
        fetchModules(token)
      ])
        .then(([completed, modules]) => {
          setCompletedModules(completed);
          setTotalModules(modules.length);
          setLoading(false);
        })
        .catch(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [token]);

  const stats = {
    menaces: 12,
    alertes: 7,
    conseils: 4,
    modules_completed: completedModules.length,
    total_modules: totalModules,
  };

  return (
    // max-w-4xl empêche l'écrasement horizontal sur grand écran. py-12 et space-y-8 aèrent le layout.
    <div className="w-full max-w-4xl mx-auto px-6 py-12 space-y-8">
      
      {/* En-tête aéré */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-gray-100 pb-5">
        <h1 className="text-2xl font-bold text-dark-blue tracking-tight">
          {user?.company_name || 'Entreprise'} 🏢
        </h1>
        <span className="text-sm text-gray-400 mt-1 sm:mt-0 font-medium">
          Aujourd'hui
        </span>
      </div>

      {/* Navigation - Liens spacieux */}
      <div className="grid grid-cols-5 gap-3 bg-white p-3 rounded-2xl shadow-sm border border-gray-100/80">
        {[
          { label: 'Profil', icon: User, href: '/profile' },
          { label: 'Alertes', icon: Bell, href: '#' },
          { label: 'Signalements', icon: AlertTriangle, href: '#' },
          { label: 'Academy', icon: BookOpen, href: '/academy' },
          { label: 'Paramètres', icon: Settings, href: '#' },
        ].map((item) => (
          <Link
            key={item.label}
            href={item.href}
            className="flex flex-col items-center justify-center py-4 px-2 rounded-xl hover:bg-gray-50 transition-all group"
          >
            <item.icon className="w-5 h-5 text-cyber-blue mb-2 group-hover:scale-105 transition-transform" />
            <span className="text-xs font-semibold text-gray-600 text-center tracking-wide">{item.label}</span>
          </Link>
        ))}
      </div>

      {/* Statistiques - Grid 2x2 sur mobile et 4 colonnes sur PC pour une lisibilité maximale */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6">
        <div className="bg-white p-5 rounded-2xl shadow-sm border border-gray-100 flex items-center justify-between min-h-[110px]">
          <div className="space-y-1">
            <p className="text-xs font-bold text-gray-400 uppercase tracking-wider">Menaces</p>
            <p className="text-3xl font-extrabold text-dark-blue">{stats.menaces}</p>
          </div>
          <div className="bg-red-50 p-2.5 rounded-xl">
            <Shield className="w-5 h-5 text-red-600" />
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl shadow-sm border border-gray-100 flex items-center justify-between min-h-[110px]">
          <div className="space-y-1">
            <p className="text-xs font-bold text-gray-400 uppercase tracking-wider">Alertes</p>
            <p className="text-3xl font-extrabold text-dark-blue">{stats.alertes}</p>
          </div>
          <div className="bg-amber-50 p-2.5 rounded-xl">
            <Bell className="w-5 h-5 text-amber-600" />
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl shadow-sm border border-gray-100 flex items-center justify-between min-h-[110px]">
          <div className="space-y-1">
            <p className="text-xs font-bold text-gray-400 uppercase tracking-wider">Conseils</p>
            <p className="text-3xl font-extrabold text-dark-blue">{stats.conseils}</p>
          </div>
          <div className="bg-blue-50 p-2.5 rounded-xl">
            <FileText className="w-5 h-5 text-blue-600" />
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl shadow-sm border border-gray-100 flex items-center justify-between min-h-[110px]">
          <div className="space-y-1">
            <p className="text-xs font-bold text-gray-400 uppercase tracking-wider">Academy</p>
            <p className="text-3xl font-extrabold text-dark-blue">
              {loading ? '...' : `${stats.modules_completed}/${stats.total_modules}`}
            </p>
          </div>
          <div className="bg-green-50 p-2.5 rounded-xl">
            <BookOpen className="w-5 h-5 text-green-600" />
          </div>
        </div>
      </div>

      {/* Barre de progression aérée */}
      <div className="bg-white p-5 rounded-2xl shadow-sm border border-gray-100 space-y-2.5">
        <div className="flex justify-between text-xs font-bold text-gray-500 uppercase tracking-wider">
          <span>Progression Academy</span>
          <span className="text-dark-blue">
            {loading ? '...' : `${Math.round((stats.modules_completed / (stats.total_modules || 1)) * 100)}%`}
          </span>
        </div>
        <div className="w-full bg-gray-100 rounded-full h-2">
          <div 
            className="bg-green-500 h-2 rounded-full transition-all duration-500 shadow-sm" 
            style={{ width: loading ? '0%' : `${(stats.modules_completed / (stats.total_modules || 1)) * 100}%` }}
          />
        </div>
      </div>

      {/* Actions - Transformation en grille robuste à 3 colonnes de taille égale */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button className="bg-cyber-blue hover:bg-blue-700 text-white text-sm font-bold py-3.5 px-4 rounded-xl flex items-center justify-center gap-2 transition shadow-sm tracking-wide">
          Voir les rapports
        </button>
        
        <button className="border-2 border-red-500 text-red-500 hover:bg-red-50 text-sm font-bold py-3.5 px-4 rounded-xl flex items-center justify-center gap-2 transition tracking-wide">
          Déclarer un incident
        </button>
        
        <Link href="/academy" className="w-full">
          <button className="bg-green-600 hover:bg-green-700 text-white text-sm font-bold py-3.5 px-4 rounded-xl flex items-center justify-center gap-2 transition shadow-sm w-full h-full tracking-wide">
            <BookOpen size={16} /> Accéder à l'Academy
          </button>
        </Link>
      </div>

      {/* Module recommandé large et aéré */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 p-6 md:p-8 rounded-2xl border border-blue-100/70 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-dark-blue flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-cyber-blue" /> Module recommandé
            </h2>
            <p className="text-sm text-gray-600 leading-relaxed">
              Protégez votre structure contre les <span className="font-semibold text-dark-blue">Faux recrutements</span> – Évitez les arnaques à l'emploi.
            </p>
          </div>
          <Link href="/academy/4" className="flex-shrink-0">
            <button className="bg-cyber-blue hover:bg-blue-700 text-white text-sm font-bold px-6 py-3 rounded-xl transition shadow-md w-full lg:w-auto">
              Commencer le module →
            </button>
          </Link>
        </div>
      </div>

    </div>
  );
}
