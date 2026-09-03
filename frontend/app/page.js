const ACTIONS = [
  {
    icon: "🛡️",
    title: "Scam-Checker",
    href: "/scam-checker",
    badge: "Vérifier une arnaque, signaler une entrée suspecte",
    enabled: true,
  },
  {
    icon: "💬",
    title: "Assistant IA",
    href: "/assistant",
    badge: "Module en cours de développement",
    enabled: false,
  },
  {
    icon: "🎓",
    title: "Academy",
    href: "/academy",
    badge: "Module en cours de développement",
    enabled: false,
  },
  {
    icon: "👤",
    title: "Mon compte",
    href: "/login",
    badge: "Connexion / Inscription",
    enabled: true,
  },
];

export default function HomePage() {
  return (
    <main className="main">
      <section className="hero">
        <h1>La cybersécurité accessible à tous les Camerounais</h1>
        <p>
          Même si vous n&apos;y connaissez rien en technologie ou en droit, vous pouvez
          utiliser CyberSafe Connect pour vous protéger, signaler une arnaque, ou
          comprendre vos droits.
        </p>
      </section>

      <div className="actions-grid">
        {ACTIONS.map((action) =>
          action.enabled ? (
            <a key={action.href} href={action.href} className="action-card enabled">
              <span className="icon">{action.icon}</span>
              <span className="title">{action.title}</span>
              <span className="badge">{action.badge}</span>
            </a>
          ) : (
            <div key={action.href} className="action-card disabled">
              <span className="icon">{action.icon}</span>
              <span className="title">{action.title}</span>
              <span className="badge">{action.badge}</span>
            </div>
          )
        )}
      </div>

      <p className="footer-note">
        CyberSafe Connect — Cybersecurity Research Laboratory (CRL)
      </p>
    </main>
  );
}
