import { useEffect, useState } from 'react'
import { getAllScans } from '../api/client'
import { Search } from 'lucide-react'

export default function HistoryPage() {
  const [scans,   setScans]   = useState([])
  const [search,  setSearch]  = useState('')
  const [filter,  setFilter]  = useState('all')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getAllScans().then(r => { setScans(r.data); setLoading(false) })
  }, [])

  const verdictColor = (v) =>
    v === 'Malicious'     ? 'bg-red-500/10 text-red-400' :
    v === 'Suspicious'    ? 'bg-amber-500/10 text-amber-400' :
    v === 'Non-Malicious' ? 'bg-emerald-500/10 text-emerald-400' :
                            'bg-gray-800 text-gray-500'

  const filtered = scans.filter(s => {
    const matchSearch = !search ||
      s.subject?.toLowerCase().includes(search.toLowerCase()) ||
      s.from_email?.toLowerCase().includes(search.toLowerCase()) ||
      s.from_domain?.toLowerCase().includes(search.toLowerCase())
    const matchFilter = filter === 'all' || s.classification === filter
    return matchSearch && matchFilter
  })

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-white">Scan history</h1>
        <p className="text-sm text-gray-500 mt-1">{scans.length} total scans</p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3 mb-5">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            className="w-full bg-gray-900 border border-gray-800 rounded-lg pl-9 pr-4 py-2.5 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-gray-600"
            placeholder="Search subject, sender, domain..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          {['all', 'Malicious', 'Suspicious', 'Non-Malicious'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-2 text-xs rounded-lg border transition-colors
                ${filter === f
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  : 'bg-gray-900 border-gray-800 text-gray-500 hover:text-gray-300'}`}
            >
              {f === 'all' ? 'All' : f}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center text-sm text-gray-600">
            No scans match your filters
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-gray-800">
                {['#', 'Subject', 'From', 'Domain', 'Score', 'Verdict', 'Date'].map(h => (
                  <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(s => (
                <tr key={s.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                  <td className="px-4 py-3 text-gray-600 text-xs">{s.id}</td>
                  <td className="px-4 py-3 text-gray-300 max-w-[180px] truncate">{s.subject || '(no subject)'}</td>
                  <td className="px-4 py-3 text-gray-400 max-w-[140px] truncate">{s.from_email || '—'}</td>
                  <td className="px-4 py-3 text-gray-400">{s.from_domain || '—'}</td>
                  <td className="px-4 py-3">
                    <span className={`font-semibold text-sm
                      ${s.score >= 70 ? 'text-red-400' :
                        s.score >= 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {s.score ?? '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {s.classification && (
                      <span className={`text-xs px-2 py-1 rounded-md font-medium ${verdictColor(s.classification)}`}>
                        {s.classification}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">{s.scanned_at?.slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}