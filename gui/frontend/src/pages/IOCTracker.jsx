import { useEffect, useState } from 'react'
import { getIOCs } from '../api/client'
import { Globe, Server, Paperclip } from 'lucide-react'

const Section = ({ title, icon: Icon, children }) => (
  <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden mb-5">
    <div className="px-5 py-4 border-b border-gray-800 flex items-center gap-2">
      <Icon size={14} className="text-red-400" />
      <h2 className="text-sm font-medium text-white">{title}</h2>
    </div>
    {children}
  </div>
)

const empty = (
  <div className="px-5 py-10 text-center text-sm text-gray-600">
    No malicious indicators found yet
  </div>
)

export default function IOCTracker() {
  const [iocs,    setIocs]    = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getIOCs().then(r => { setIocs(r.data); setLoading(false) })
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-white">IOC Tracker</h1>
        <p className="text-sm text-gray-500 mt-1">Aggregated malicious indicators across all scans</p>
      </div>

      <Section title="Malicious IPs" icon={Server}>
        {iocs.malicious_ips.length === 0 ? empty : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-gray-800">
                {['IP', 'Country', 'ASN Owner', 'Abuse Score', 'Seen in scans'].map(h => (
                  <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {iocs.malicious_ips.map((r, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 text-red-400 font-mono text-xs">{r.ip}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{r.country || '—'}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{r.asn_owner || '—'}</td>
                  <td className="px-4 py-3 text-amber-400 text-xs">{r.abuse_confidence}</td>
                  <td className="px-4 py-3 text-gray-300 text-xs">{r.seen_in_scans}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="Malicious URLs" icon={Globe}>
        {iocs.malicious_urls.length === 0 ? empty : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-gray-800">
                {['URL', 'Detections', 'Seen in scans'].map(h => (
                  <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {iocs.malicious_urls.map((r, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 text-red-400 font-mono text-xs max-w-sm truncate">{r.url}</td>
                  <td className="px-4 py-3 text-amber-400 text-xs">{r.detections}</td>
                  <td className="px-4 py-3 text-gray-300 text-xs">{r.seen_in_scans}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="Malicious file hashes" icon={Paperclip}>
        {iocs.malicious_hashes.length === 0 ? empty : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-gray-800">
                {['Filename', 'SHA256', 'Detections', 'Seen in scans'].map(h => (
                  <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {iocs.malicious_hashes.map((r, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 text-gray-300 text-xs">{r.filename || '—'}</td>
                  <td className="px-4 py-3 text-red-400 font-mono text-xs max-w-xs truncate">{r.sha256}</td>
                  <td className="px-4 py-3 text-amber-400 text-xs">{r.detections}</td>
                  <td className="px-4 py-3 text-gray-300 text-xs">{r.seen_in_scans}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  )
}