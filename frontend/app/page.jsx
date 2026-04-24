"use client";

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { PolarAngleAxis, RadialBar, RadialBarChart, ResponsiveContainer } from "recharts";

import { StatusBadge } from "../components/ui/badge";
import { Card } from "../components/ui/card";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8001/api";

function ScoreRing({ score }) {
  const data = [{ name: "Score", value: score }];
  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart data={data} innerRadius="70%" outerRadius="100%" startAngle={90} endAngle={-270}>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar dataKey="value" cornerRadius={12} fill="#22c55e" />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="-mt-36 text-center">
        <p className="text-4xl font-bold">{Math.round(score)}%</p>
        <p className="text-slate-400 text-sm">Security Score</p>
      </div>
    </div>
  );
}

export default function Page() {
  const [summary, setSummary] = useState({ total_audits: 0, completed_audits: 0, average_score: 0, average_coverage: 0 });
  const [audits, setAudits] = useState([]);
  const [liveScore, setLiveScore] = useState(0);
  const [form, setForm] = useState({ name: "Weekly Cloud Audit", provider: "aws", framework: "CIS", tool: "internal" });

  async function load() {
    const [summaryRes, auditsRes] = await Promise.all([
      fetch(`${API_BASE}/dashboard/summary`, { cache: "no-store" }),
      fetch(`${API_BASE}/audits`, { cache: "no-store" }),
    ]);
    const nextSummary = await summaryRes.json();
    setSummary(nextSummary);
    setLiveScore(Number(nextSummary.average_score || 0));
    setAudits(await auditsRes.json());
  }

  useEffect(() => {
    load();
    const refresh = setInterval(load, 15000);
    const pulse = setInterval(() => {
      setLiveScore((prev) => {
        const target = Number(summary.average_score || 0);
        const jitter = Math.random() * 5 - 2.5;
        return Math.max(0, Math.min(100, target + jitter + prev * 0.05));
      });
    }, 5000);
    return () => {
      clearInterval(refresh);
      clearInterval(pulse);
    };
  }, [summary.average_score]);

  const criticalIssues = useMemo(
    () => audits.filter((a) => String(a.status).toLowerCase() === "failed").length,
    [audits]
  );
  const passedChecksEstimate = useMemo(() => audits.reduce((acc, a) => acc + (a.score >= 80 ? 1 : 0), 0), [audits]);

  async function createAudit(event) {
    event.preventDefault();
    await fetch(`${API_BASE}/audits`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });
    await load();
  }

  async function runAudit(id) {
    await fetch(`${API_BASE}/audits/${id}/trigger`, { method: "POST" });
    await load();
  }

  return (
    <div className="min-h-screen bg-bg text-text">
      <aside className="fixed left-0 top-0 h-screen w-60 bg-side border-r border-slate-800 p-6">
        <h1 className="text-2xl font-bold tracking-wide text-emerald-400">AuditSec</h1>
        <ul className="mt-8 space-y-3 text-slate-300">
          <li className="rounded-md bg-slate-800 px-3 py-2">Overview</li>
          <li className="rounded-md px-3 py-2 hover:bg-slate-800/70">Findings</li>
          <li className="rounded-md px-3 py-2 hover:bg-slate-800/70">Scans</li>
          <li className="rounded-md px-3 py-2 hover:bg-slate-800/70">Settings</li>
        </ul>
      </aside>

      <main className="ml-60 p-8">
        <motion.h2
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-3xl font-semibold mb-6"
        >
          Cloud Security Command Center
        </motion.h2>

        <section className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <Card>
            <p className="text-slate-400 text-sm">Threat Score</p>
            <p className="text-2xl font-bold text-warning mt-2">{Math.round(liveScore)}%</p>
          </Card>
          <Card>
            <p className="text-slate-400 text-sm">Critical Issues</p>
            <p className="text-2xl font-bold text-danger mt-2">{criticalIssues}</p>
          </Card>
          <Card>
            <p className="text-slate-400 text-sm">Passed Checks</p>
            <p className="text-2xl font-bold text-success mt-2">{passedChecksEstimate}</p>
          </Card>
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          <Card title="Security Posture">
            <ScoreRing score={liveScore} />
          </Card>

          <Card title="Create Audit" className="lg:col-span-2">
            <form onSubmit={createAudit} className="flex flex-wrap gap-3">
              <input
                className="flex-1 min-w-56 rounded-md bg-slate-900 border border-slate-700 px-3 py-2"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Audit name"
              />
              <select
                className="rounded-md bg-slate-900 border border-slate-700 px-3 py-2"
                value={form.provider}
                onChange={(e) => setForm({ ...form, provider: e.target.value })}
              >
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
                <option value="m365">M365</option>
                <option value="multi">Multi</option>
              </select>
              <select
                className="rounded-md bg-slate-900 border border-slate-700 px-3 py-2"
                value={form.tool}
                onChange={(e) => setForm({ ...form, tool: e.target.value })}
              >
                <option value="internal">Internal</option>
                <option value="prowler">Prowler</option>
                <option value="maester">Maester</option>
                <option value="steampipe">Steampipe</option>
              </select>
              <select
                className="rounded-md bg-slate-900 border border-slate-700 px-3 py-2"
                value={form.framework}
                onChange={(e) => setForm({ ...form, framework: e.target.value })}
              >
                <option value="CIS">CIS</option>
                <option value="NIST">NIST</option>
                <option value="ISO27001">ISO27001</option>
                <option value="CUSTOM">Custom</option>
              </select>
              <button className="rounded-md bg-emerald-500 hover:bg-emerald-400 text-slate-950 px-4 py-2 font-semibold">
                Launch Audit
              </button>
            </form>
          </Card>
        </section>

        <Card title="Audit Runs">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-slate-400 border-b border-slate-700">
                  <th className="text-left py-3">Name</th>
                  <th className="text-left py-3">Provider</th>
                  <th className="text-left py-3">Tool</th>
                  <th className="text-left py-3">Status</th>
                  <th className="text-left py-3">Score</th>
                  <th className="text-left py-3">Coverage</th>
                  <th className="text-left py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((audit) => (
                  <tr key={audit.id} className="border-b border-slate-800">
                    <td className="py-3">{audit.name}</td>
                    <td className="py-3 uppercase">{audit.provider}</td>
                    <td className="py-3 uppercase">{audit.tool}</td>
                    <td className="py-3">
                      <StatusBadge status={audit.status} />
                    </td>
                    <td className={`py-3 font-semibold ${audit.score >= 80 ? "text-success" : "text-danger"}`}>
                      {audit.score}
                    </td>
                    <td className="py-3">{audit.coverage_percent ?? 0}%</td>
                    <td className="py-3 space-x-2">
                      <button
                        className="rounded border border-slate-600 px-2 py-1 hover:bg-slate-800"
                        onClick={() => runAudit(audit.id)}
                      >
                        Run
                      </button>
                      <a
                        className="rounded border border-slate-600 px-2 py-1 hover:bg-slate-800 inline-block"
                        href={`${API_BASE}/reports/${audit.id}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        JSON
                      </a>
                      <a
                        className="rounded border border-slate-600 px-2 py-1 hover:bg-slate-800 inline-block"
                        href={`${API_BASE}/reports/${audit.id}?format=pdf`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        PDF
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </main>
    </div>
  );
}
