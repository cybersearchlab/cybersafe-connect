import "./globals.css";
import AuthNav from "./AuthNav";

export const metadata = {
  title: "CyberSafe Connect",
  description: "La cybersécurité accessible à tous les Camerounais",
};

const NAV_ITEMS = [
  { label: "Scam-Checker", href: "/scam-checker", enabled: true },
  { label: "Assistant IA", href: "/assistant", enabled: false },
  { label: "Academy", href: "/academy", enabled: false },
];

export default function RootLayout({ children }) {
  return (
    <html lang="fr">
      <body>
        <header className="header">
          <a href="/" className="logo">
            CyberSafe<span>Connect</span>
          </a>
          <nav className="nav">
            {NAV_ITEMS.map((item) =>
              item.enabled ? (
                <a key={item.href} href={item.href}>
                  {item.label}
                </a>
              ) : (
                <span key={item.href} className="disabled" title="Module en cours de développement">
                  {item.label}
                </span>
              )
            )}
            <AuthNav />
          </nav>
        </header>
        {children}
      </body>
    </html>
  );
}
