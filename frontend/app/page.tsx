'use client'
import Link from 'next/link'
import { Shield, AlertTriangle, FileText, Scale } from 'lucide-react'

export default function Home() {
  return (
    <div className="max-w-7xl mx-auto px-4 py-12">
      <div className="text-center mb-12">
        <div className="inline-flex p-3 bg-dark-blue rounded-full mb-4">
          <Shield className="w-12 h-12 text-cyber-blue" />
        </div>
        <h1 className="text-4xl font-bold text-dark-blue mb-2">CyberSafe APP</h1>
        <p className="text-xl text-gray-600">Plateforme intelligente de sensibilisation et de protection juridique contre la cybercriminalité au Cameroun</p>
        <div className="flex gap-4 justify-center mt-6">
          <Link href="/login" className="bg-cyber-blue text-white px-6 py-2 rounded-lg hover:bg-blue-700">Se connecter</Link>
          <Link href="/register" className="border border-cyber-blue text-cyber-blue px-6 py-2 rounded-lg hover:bg-blue-50">Créer un compte</Link>
        </div>
      </div>
      <div className="grid md:grid-cols-4 gap-6 mt-12">
        <div className="bg-white p-6 rounded-xl shadow-md text-center"><AlertTriangle className="mx-auto mb-2 text-cyber-blue" /> Vérification des arnaques</div>
        <div className="bg-white p-6 rounded-xl shadow-md text-center"><FileText className="mx-auto mb-2 text-cyber-blue" /> Signalement d'incidents</div>
        <div className="bg-white p-6 rounded-xl shadow-md text-center"><Shield className="mx-auto mb-2 text-cyber-blue" /> Conseils de cybersécurité</div>
        <div className="bg-white p-6 rounded-xl shadow-md text-center"><Scale className="mx-auto mb-2 text-cyber-blue" /> Assistance juridique</div>
      </div>
    </div>
  )
}