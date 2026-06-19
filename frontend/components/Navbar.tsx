'use client'
import Link from 'next/link'
import { useAuth } from '@/context/AuthContext'
import { Shield, LogOut, User } from 'lucide-react'

export default function Navbar() {
  const { user, logout } = useAuth()
  return (
    <nav className="bg-dark-blue text-white shadow-md">
      <div className="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
        <Link href="/" className="flex items-center space-x-2">
          <Shield className="w-6 h-6 text-cyber-blue" />
          <span className="font-bold text-xl">CyberSafe APP</span>
        </Link>
        <div className="flex items-center space-x-4">
          {user ? (
            <>
              <Link href={user.role === 'company' ? '/dashboard/company' : '/dashboard/citizen'} className="hover:text-gray-300">Dashboard</Link>
              <Link href="/profile" className="hover:text-gray-300"><User size={18} /></Link>
              <button onClick={logout} className="flex items-center gap-1 hover:text-red-400"><LogOut size={18} /> Déconnexion</button>
            </>
          ) : (
            <>
              <Link href="/login" className="hover:text-gray-300">Connexion</Link>
              <Link href="/register" className="bg-cyber-blue px-4 py-1 rounded-lg">Inscription</Link>
            </>
          )}
        </div>
      </div>
    </nav>
  )
}