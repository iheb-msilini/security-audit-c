const statusClass = {
  completed: "text-success border-success/50 bg-success/10",
  failed: "text-danger border-danger/50 bg-danger/10",
  running: "text-warning border-warning/50 bg-warning/10",
  pending: "text-slate-300 border-slate-500/50 bg-slate-600/20",
};

export function StatusBadge({ status = "pending" }) {
  const key = String(status).toLowerCase();
  return (
    <span className={`px-2 py-1 text-xs rounded-full border ${statusClass[key] || statusClass.pending}`}>
      {status}
    </span>
  );
}
