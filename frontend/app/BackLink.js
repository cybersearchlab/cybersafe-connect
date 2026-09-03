export default function BackLink({ href = "/", label = "Retour à l'accueil" }) {
  return (
    <a href={href} className="back-link" aria-label={label} title={label}>
      <svg
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M19 12H5" />
        <path d="M12 19l-7-7 7-7" />
      </svg>
    </a>
  );
}
