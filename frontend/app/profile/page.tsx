'use client'
import { useAuth } from '@/context/AuthContext'

export default function ProfilePage() {
  const { user } = useAuth()
  if (!user) return <div className="text-center mt-20">Chargement...</div>
  return (
    <div className="max-w-2xl mx-auto mt-10 p-6 bg-white rounded-xl shadow">
      <h2 className="text-2xl font-bold mb-4">Mon Profil</h2>
      <div className="space-y-3">
        <div><label className="font-semibold">Nom :</label> {user.username || user.email}</div>
        <div><label className="font-semibold">Email :</label> {user.email}</div>
        <div><label className="font-semibold">Téléphone :</label> {user.phone || 'Non renseigné'}</div>
        <div><label className="font-semibold">Adresse :</label> {user.address || 'Non renseignée'}</div>
        {user.company_name && <div><label className="font-semibold">Entreprise :</label> {user.company_name}</div>}
      </div>
      <button className="mt-4 text-cyber-blue">Modifier</button>
    </div>
  )
}