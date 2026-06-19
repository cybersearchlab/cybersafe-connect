'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, Video, FileText, BookOpen, Award, ShieldCheck } from 'lucide-react';
import { fetchModule } from '@/lib/api';
import type { ModuleDetail } from '@/lib/api';

export default function ModuleDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [module, setModule] = useState<ModuleDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (id) {
      fetchModule(Number(id))
        .then(data => setModule(data))
        .catch(console.error)
        .finally(() => setLoading(false));
    }
  }, [id]);

  if (loading) return <div className="p-8 text-center text-gray-500">Chargement...</div>;
  if (!module) return <div className="p-8 text-center text-red-500">Module non trouvé.</div>;

  // Fonction pour transformer les liens YouTube/Vimeo en embed
  const getEmbedUrl = (url: string) => {
    if (url.includes('youtube.com/watch')) {
      return url.replace('watch?v=', 'embed/');
    }
    if (url.includes('youtu.be/')) {
      const id = url.split('youtu.be/')[1].split('?')[0];
      return `https://www.youtube.com/embed/${id}`;
    }
    if (url.includes('vimeo.com/')) {
      const id = url.split('vimeo.com/')[1].split('/')[0];
      return `https://player.vimeo.com/video/${id}`;
    }
    return url;
  };

  return (
    <div className="max-w-3xl mx-auto p-6 bg-white rounded-xl shadow">
      <button onClick={() => router.back()} className="text-cyber-blue mb-4 hover:underline flex items-center gap-1">
        <ArrowLeft className="w-4 h-4" /> Retour
      </button>

      {/* === IMAGE DE COUVERTURE DU MODULE === */}
      {module.image && (
        <div className="mb-4 -mt-1">
          <img
            src={`${process.env.NEXT_PUBLIC_API_URL}${module.image}`}
            alt={module.title}
            className="w-full h-48 md:h-56 object-cover rounded-xl"
          />
        </div>
      )}

      <h1 className="text-2xl font-bold text-dark-blue flex items-center gap-2">
        <ShieldCheck className="w-6 h-6 text-cyber-blue" />
        {module.title}
      </h1>
      <p className="text-gray-600 mt-2">{module.description}</p>

      {/* Vidéo locale (uploadée) */}
      {module.video_file && (
        <div className="mt-6">
          <h2 className="font-semibold mb-2 flex items-center gap-1">
            <Video className="w-5 h-5 text-cyber-blue" /> Vidéo
          </h2>
          <video
            controls
            className="w-full rounded-lg shadow"
            src={`${process.env.NEXT_PUBLIC_API_URL}${module.video_file}`}
          >
            Votre navigateur ne supporte pas la lecture vidéo.
          </video>
        </div>
      )}

      {/* Vidéo en ligne (YouTube/Vimeo) - seulement si pas de vidéo locale */}
      {module.video_url && !module.video_file && (
        <div className="mt-6">
          <h2 className="font-semibold mb-2 flex items-center gap-1">
            <Video className="w-5 h-5 text-cyber-blue" /> Vidéo en ligne
          </h2>
          <div className="aspect-w-16 aspect-h-9">
            <iframe
              src={getEmbedUrl(module.video_url)}
              className="w-full h-64 rounded-lg"
              allowFullScreen
              title="Vidéo du module"
            />
          </div>
        </div>
      )}

      {/* PDF */}
      {module.pdf_file && (
        <div className="mt-6">
          <h2 className="font-semibold mb-2 flex items-center gap-1">
            <FileText className="w-5 h-5 text-cyber-blue" /> Ressource PDF
          </h2>
          <a
            href={`${process.env.NEXT_PUBLIC_API_URL}${module.pdf_file}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyber-blue underline hover:text-blue-700"
          >
            Télécharger le PDF
          </a>
        </div>
      )}

      {/* Contenu textuel */}
      <div className="mt-6 prose prose-blue max-w-none">
        <h2 className="font-semibold text-dark-blue flex items-center gap-1">
          <BookOpen className="w-5 h-5 text-cyber-blue" /> Contenu
        </h2>
        <div className="whitespace-pre-wrap">{module.content}</div>
      </div>

      {/* Bouton vers le quiz */}
      <Link href={`/academy/${module.id}/quiz`}>
        <button className="mt-8 w-full bg-green-600 text-white px-6 py-3 rounded-lg hover:bg-green-700 transition flex items-center justify-center gap-2">
          <Award className="w-5 h-5" /> Tester mes connaissances
        </button>
      </Link>
    </div>
  );
}