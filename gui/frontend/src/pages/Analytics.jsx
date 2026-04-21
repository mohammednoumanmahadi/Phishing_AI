import { useEffect, useState } from 'react'
import { getAllScans } from '../api/client'
import {
  PieChart, Pie, Cell,
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer
} from 'recharts'

const COLORS = {
  'Malicious':     '#f87171',
  'Suspicious':    '#fbbf24',
  'Non-Malicious': '#34d399',
}

export default function Analytics() {
  const [scans, setScans] = useState([])

  useEffect(() => {
    getAllScans().then(r => setScans(r.data))
  }, [])

  // verdict pie
  const counts = scans.reduce((acc, s) => {
    const k = s.classification || 'Unknown'
    acc[k] = (acc[k] || 0) + 1
    return acc
  }, {})
  const pieData = Object.entries(counts).map(([name, value]) => ({ name, value }))

  // score distribution
  const buckets = { '0–20': 0, '21–40': 0, '41–60': 0, '61–80': 0, '81–100': 0 }
  scans.forEach(s => {
    if      (s.score <= 20) buckets['0–20']++
    else if (s.score <= 40) buckets['21–40']++
    else if (s.score <= 60) buckets['41–60']++
    else if (s.score <= 80) buckets['61–80']++
    else                    buckets['81–100']++
  })
  const barData = Object.entries(buckets).map(([range, count]) => ({ range, count }))

  // auth pass rates
  const total     = scans.length || 1
  const authData  = [
    { name: 'SPF',   pass: Math.round((scans.filter(s => s.spf   === 'pass').length / total) * 100) },
    { name: 'DKIM',  pass: Math.round((scans.filter(s => s.dkim  === 'pass').length / total) * 100) },
    { name: 'DMARC', pass: Math.round((scans.filter(s => s.dmarc === 'pass').length / total) * 100) },
  ]

  if (scans.length === 0) return (
    <div className="flex items-center justify-center h-full">
      <p className="text-sm text-gray-600">No data yet — scan some emails first</p>
    </div>
  )

  const tooltipStyle = {
    background: '#111827',
    border: '1px solid #1f2937',
    borderRadius: 8,
    fontSize: 12
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-white">Analytics</h1>
        <p className="text-sm text-gray-500 mt-1">Trends and patterns across {scans.length} scans</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

        {/* verdict pie */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-white mb-4">Verdict distribution</h2>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%" cy="50%"
                outerRadius={80}
                dataKey="value"
                label={({ name, percent }) => `${name} ${Math.round(percent * 100)}%`}
                labelLine={false}
              >
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={COLORS[entry.name] || '#6b7280'} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* score distribution */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-white mb-4">Risk score distribution</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={barData}>
              <XAxis dataKey="range" tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* auth pass rates */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 md:col-span-2">
          <h2 className="text-sm font-medium text-white mb-4">Authentication pass rates (%)</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={authData} layout="vertical">
              <XAxis type="number" domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} formatter={(v) => `${v}%`} />
              <Bar dataKey="pass" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

      </div>
    </div>
  )
}