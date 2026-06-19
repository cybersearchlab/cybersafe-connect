'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { registerUser } from '@/lib/api'

export default function RegisterPage() {
  const [step, setStep] = useState<'choice' | 'form'>('choice')
  const [role, setRole] = useState<'citizen' | 'company'>('citizen')
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const payload = {
      email: formData.get('email'),
      password: formData.get('password'),
      role: role,
      phone: formData.get('phone'),
      address: formData.get('address'),
      company_name: role === 'company' ? formData.get('company_name') : '',
      sector: role === 'company' ? formData.get('sector') : '',
    }
    try {
      await registerUser(payload)
      router.push('/login')
    } catch (error: any) {
      alert('Erreur: ' + error.message)
    }
  }

  if (step === 'choice') {
    return (
      <div className="max-w-md mx-auto mt-20 p-8 bg-white rounded-xl shadow-lg">
        <h2 className="text-2xl font-bold mb-6">Créer un compte</h2>
        <p className="mb-4">Je suis :</p>
        <div className="space-y-3 mb-6">
          <label className="flex items-center space-x-3 p-3 border rounded-lg cursor-pointer">
            <input type="radio" name="role" value="citizen" checked={role === 'citizen'} onChange={() => setRole('citizen')} /> 
            <span>Citoyen</span>
          </label>
          <label className="flex items-center space-x-3 p-3 border rounded-lg cursor-pointer">
            <input type="radio" name="role" value="company" checked={role === 'company'} onChange={() => setRole('company')} /> 
            <span>Entreprise</span>
          </label>
        </div>
        <button onClick={() => setStep('form')} className="w-full bg-cyber-blue text-white py-2 rounded-lg">Continuer</button>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-md mx-auto mt-20 p-8 bg-white rounded-xl shadow-lg space-y-4">
      <h2 className="text-2xl font-bold">{role === 'citizen' ? 'Inscription Citoyen' : 'Inscription Entreprise'}</h2>
      {role === 'company' && (
        <>
          <input name="company_name" placeholder="Nom de l'entreprise" className="w-full p-3 border rounded-lg" required />
          <input name="sector" placeholder="Secteur d'activité" className="w-full p-3 border rounded-lg" />
        </>
      )}
      <input name="email" type="email" placeholder="Email" className="w-full p-3 border rounded-lg" required />
      <input name="phone" placeholder="Téléphone" className="w-full p-3 border rounded-lg" />
      <input name="address" placeholder="Adresse" className="w-full p-3 border rounded-lg" />
      <input name="password" type="password" placeholder="Mot de passe" className="w-full p-3 border rounded-lg" required />
      <button type="submit" className="w-full bg-cyber-blue text-white py-3 rounded-lg">Créer mon compte</button>
    </form>
  )
}