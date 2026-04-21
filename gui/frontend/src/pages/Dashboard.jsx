import { useEffect, useState } from 'react'
import { getStats, getAllScans } from '../api/client'
import { ShieldAlert, ShieldCheck, ShieldX, Activity, Link, Paperclip } from 'lucide-react'

const StatCard = ({ label, value, icon: Icon, color }) => (
  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-center gap-4">
    <div className={`p-3 rounded-lg ${color}`}>
      <Icon size={18} />
    </div>
    <div>
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className="text-2xl font-semibold text-white">{value}</p>
    </div>
  </div>
)

const verdictBadge = (v) => {
  if (!v) return <span className="text-gray-500 text-xs">—</span>
  const map = {
    'Malicious':     'bg-red-500/10 text-red-400',
    'Suspicious':    'bg-amber-500/10 text-amber-400',
    'Non-Malicious': 'bg-emerald-500/10 text-emerald-400',
  }
  return <span className={`text-xs px-2 py-1 rounded-md font-medium ${map[v] || 'bg-gray-800 text-gray-400'}`}>{v}</span>
}

export default function Dashboard() {
  const [stats,   setStats]   = useState(null)
  const [scans,   setScans]   = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([getStats(), getAllScans()]).then(([s, sc]) => {
      setStats(s.data)
      setScans(sc.data.slice(0, 8))
      setLoading(false)
    })
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <div className="w-6 h-6 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-white">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">Overview of your phishing analysis activity</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total scans"  value={stats.total_scans}  icon={Activity}    color="bg-blue-500/10 text-blue-400"       />
        <StatCard label="Malicious"    value={stats.malicious}    icon={ShieldX}     color="bg-red-500/10 text-red-400"         />
        <StatCard label="Suspicious"   value={stats.suspicious}   icon={ShieldAlert} color="bg-amber-500/10 text-amber-400"     />
        <StatCard label="Clean"        value={stats.clean}        icon={ShieldCheck} color="bg-emerald-500/10 text-emerald-400" />
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        <StatCard label="Avg risk score"        value={stats.avg_risk_score}        icon={Activity}  color="bg-purple-500/10 text-purple-400" />
        <StatCard label="Malicious URLs"        value={stats.malicious_urls}        icon={Link}      color="bg-red-500/10 text-red-400"       />
        <StatCard label="Malicious attachments" value={stats.malicious_attachments} icon={Paperclip} color="bg-amber-500/10 text-amber-400"   />
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800">
          <h2 className="text-sm font-medium text-white">Recent scans</h2>
        </div>
        {scans.length === 0 ? (
          <div className="px-5 py-12 text-center text-sm text-gray-600">
            No scans yet — upload an email to get started
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-gray-800">
                {['Subject', 'From', 'Score', 'Verdict', 'Date'].map(h => (
                  <th key={h} className="px-5 py-3 text-left font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr key={s.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                  <td className="px-5 py-3 text-gray-300 max-w-xs truncate">{s.subject || '(no subject)'}</td>
                  <td className="px-5 py-3 text-gray-400 truncate">{s.from_email || '—'}</td>
                  <td className="px-5 py-3">
                    <span className={`font-semibold ${s.score >= 70 ? 'text-red-400' : s.score >= 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {s.score ?? '—'}
                    </span>
                  </td>
                  <td className="px-5 py-3">{verdictBadge(s.classification)}</td>
                  <td className="px-5 py-3 text-gray-500">{s.scanned_at?.slice(0, 10) || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}