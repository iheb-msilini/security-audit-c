export function Card({ title, children, className = "" }) {
  return (
    <section className={`rounded-xl bg-card p-5 shadow-soft border border-slate-700 ${className}`}>
      {title ? <h3 className="text-lg font-semibold mb-4">{title}</h3> : null}
      {children}
    </section>
  );
}
