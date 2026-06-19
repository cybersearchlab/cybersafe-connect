'use client';
import { useAuth } from '@/context/AuthContext';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Shield, AlertTriangle, BookOpen, User, Bell, Settings, TrendingUp } from 'lucide-react';
import { fetchProgress, fetchModules } from '@/lib/api';

export default function CitizenDashboard() {
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
    signalements: 3,
    alertes: 5,
    modules_completed: completedModules.length,
    total_modules: totalModules,
  };

  return (
    <div className="w-full max-w-full px-3 py-3">
      <div className="flex items-center justify-between mb-3">
        <h1 className="text-lg font-bold text-dark-blue">
          Bonjour {user?.email?.split('@')[0] || 'Utilisateur'} 👋
        </h1>
        <span className="text-xs text-gray-400">Aujourd'hui</span>
      </div>

      <div className="grid grid-cols-5 gap-1 bg-white p-1.5 rounded-lg shadow-sm mb-3">
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
            className="flex flex-col items-center py-1.5 rounded hover:bg-gray-100 transition-colors"
          >
            <item.icon className="w-4 h-4 text-cyber-blue" />
            <span className="text-[10px] font-medium text-gray-600">{item.label}</span>
          </Link>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-2 mb-3">
        <div className="bg-white p-3 rounded-lg shadow-sm border border-gray-100 flex items-center justify-between">
          <div>
            <p className="text-[10px] text-gray-400 uppercase tracking-wide">Signalements</p>
            <p className="text-xl font-bold text-dark-blue">{stats.signalements}</p>
          </div>
          <div className="bg-red-100 p-1.5 rounded-full">
            <AlertTriangle className="w-4 h-4 text-red-600" />
          </div>
        </div>
        <div className="bg-white p-3 rounded-lg shadow-sm border border-gray-100 flex items-center justify-between">
          <div>
            <p className="text-[10px] text-gray-400 uppercase tracking-wide">Alertes</p>
            <p className="text-xl font-bold text-dark-blue">{stats.alertes}</p>
          </div>
          <div className="bg-amber-100 p-1.5 rounded-full">
            <Bell className="w-4 h-4 text-amber-600" />
          </div>
        </div>
        <div className="bg-white p-3 rounded-lg shadow-sm border border-gray-100 flex items-center justify-between">
          <div>
            <p className="text-[10px] text-gray-400 uppercase tracking-wide">Academy</p>
            <p className="text-xl font-bold text-dark-blue">
              {loading ? '...' : `${stats.modules_completed}/${stats.total_modules}`}
            </p>
          </div>
          <div className="bg-green-100 p-1.5 rounded-full">
            <BookOpen className="w-4 h-4 text-green-600" />
          </div>
        </div>
      </div>

      <div className="bg-white p-2 rounded-lg shadow-sm border border-gray-100 mb-3">
        <div className="flex justify-between text-[10px] text-gray-500 mb-0.5">
          <span>Progression Academy</span>
          <span>{loading ? '...' : `${Math.round((stats.modules_completed / (stats.total_modules || 1)) * 100)}%`}</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-1.5">
          <div 
            className="bg-green-500 h-1.5 rounded-full transition-all" 
            style={{ width: loading ? '0%' : `${(stats.modules_completed / (stats.total_modules || 1)) * 100}%` }}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-3">
        <button className="bg-red-600 hover:bg-red-700 text-white text-xs px-3 py-1.5 rounded-lg flex items-center justify-center gap-1 transition shadow-sm">
          <AlertTriangle size={14} /> Signaler
        </button>
        <button className="border border-cyber-blue text-cyber-blue hover:bg-blue-50 text-xs px-3 py-1.5 rounded-lg flex items-center justify-center gap-1 transition">
          <Shield size={14} /> Vérifier
        </button>
        <Link href="/academy">
          <button className="bg-green-600 hover:bg-green-700 text-white text-xs px-3 py-1.5 rounded-lg transition shadow-sm">
            <BookOpen size={14} className="inline mr-1" /> Academy
          </button>
        </Link>
      </div>

      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 p-3 rounded-lg border border-blue-100">
        <div className="flex items-center justify-between gap-2">
          <div className="flex-1 min-w-0">
            <h2 className="text-xs font-semibold text-dark-blue flex items-center gap-1">
              <TrendingUp className="w-3 h-3 text-cyber-blue" /> Module recommandé
            </h2>
            <p className="text-[11px] text-gray-600 truncate">
              <span className="font-medium">Sécurité Mobile Money</span> – Apprenez à sécuriser vos transactions.
            </p>
          </div>
          <Link href="/academy/1" className="flex-shrink-0">
            <button className="bg-cyber-blue hover:bg-blue-700 text-white text-[10px] px-3 py-1 rounded transition whitespace-nowrap">
              Commencer →
            </button>
          </Link>
        </div>
      </div>
    </div>
  );
}