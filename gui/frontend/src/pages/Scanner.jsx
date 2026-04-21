import { useState, useRef } from 'react'
import { scanEmail } from '../api/client'
import { Upload, ShieldX, ShieldCheck, ShieldAlert, FileText, Globe, Paperclip, Server } from 'lucide-react'

const Badge = ({ v }) => {
  const map = {
    pass: 'bg-emerald-500/10 text-emerald-400',
    fail: 'bg-red-500/10 text-red-400',
    none: 'bg-gray-800 text-gray-500'
  }
  const k = v === 'pass' ? 'pass' : v === 'fail' ? 'fail' : 'none'
  return (
    <span className={`text-xs px-2 py-1 rounded-md font-medium uppercase ${map[k]}`}>
      {v || 'unknown'}
    </span>
  )
}

export default function Scanner() {
  const [dragging, setDragging] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [result,   setResult]   = useState(null)
  const [error,    setError]    = useState(null)
  const [progress, setProgress] = useState('')
  const fileRef = useRef()

  const steps = [
    'Parsing email headers...',
    'Extracting URLs and attachments...',
    'Checking IP reputation...',
    'Scanning URLs with VirusTotal...',
    'Running domain analysis...',
    'Calculating risk score...',
    'Generating SOC report...',
  ]

  const runScan = async (file) => {
    if (!file?.name.endsWith('.eml')) {
      setError('Only .eml files are supported')
      return
    }
    setError(null)
    setResult(null)
    setScanning(true)

    let i = 0
    const interval = setInterval(() => {
      setProgress(steps[i % steps.length])
      i++
    }, 4000)

    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await scanEmail(fd)
      setResult(res.data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Scan failed — check server logs')
    } finally {
      clearInterval(interval)
      setScanning(false)
      setProgress('')
    }
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    runScan(e.dataTransfer.files[0])
  }

  const risk  = result?.risk
  const email = result?.email
  const intel = result?.intel
  const soc   = result?.soc_report

  const scoreColor = !risk ? '' :
    risk.score >= 70 ? 'text-red-400' :
    risk.score >= 40 ? 'text-amber-400' : 'text-emerald-400'

  const ScoreIcon = !risk ? ShieldCheck :
    risk.score >= 70 ? ShieldX :
    risk.score >= 40 ? ShieldAlert : ShieldCheck

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-white">Scan Email</h1>
        <p className="text-sm text-gray-500 mt-1">Upload a .eml file to run full phishing analysis</p>
      </div>

      {/* drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => fileRef.current.click()}
        className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors mb-6
          ${dragging
            ? 'border-emerald-400 bg-emerald-500/5'
            : 'border-gray-700 hover:border-gray-600 bg-gray-900'}`}
      >
        <Upload size={32} className="mx-auto mb-3 text-gray-500" />
        <p className="text-sm text-gray-400">
          Drag & drop a <span className="text-emerald-400">.eml</span> file here
        </p>
        <p className="text-xs text-gray-600 mt-1">or click to browse</p>
        <input
          ref={fileRef}
          type="file"
          accept=".eml"
          className="hidden"
          onChange={(e) => runScan(e.target.files[0])}
        />
      </div>

      {/* scanning progress */}
      {scanning && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6 flex items-center gap-4">
          <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin flex-shrink-0" />
          <div>
            <p className="text-sm text-white font-medium">Analyzing email...</p>
            <p className="text-xs text-gray-500 mt-1">{progress}</p>
          </div>
        </div>
      )}

      {/* error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 mb-6 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* results */}
      {result && (
        <div className="flex flex-col gap-5">

          {/* risk score card */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex items-center gap-6">
            <ScoreIcon size={40} className={scoreColor} />
            <div className="flex-1">
              <p className="text-xs text-gray-500 mb-1">Risk score</p>
              <p className={`text-4xl font-semibold ${scoreColor}`}>
                {risk.score}
                <span className="text-lg text-gray-600">/100</span>
              </p>
              <p className="text-sm text-gray-400 mt-1">{risk.verdict}</p>
            </div>
            <span className={`text-sm font-medium px-3 py-1.5 rounded-lg
              ${soc.classification === 'Malicious'     ? 'bg-red-500/10 text-red-400' :
                soc.classification === 'Suspicious'    ? 'bg-amber-500/10 text-amber-400' :
                                                         'bg-emerald-500/10 text-emerald-400'}`}>
              {soc.classification}
            </span>
          </div>

          {/* email details + auth */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-medium text-white mb-4 flex items-center gap-2">
                <FileText size={14} /> Email details
              </h3>
              {[
                ['Subject',     email.subject],
                ['From',        email.from_email],
                ['Domain',      email.from_domain],
                ['Return-path', email.return_path],
                ['Sender IP',   email.sender_ip],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between py-1.5 border-b border-gray-800/50 last:border-0">
                  <span className="text-xs text-gray-500">{k}</span>
                  <span className="text-xs text-gray-300 max-w-[180px] truncate text-right">{v || '—'}</span>
                </div>
              ))}
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-medium text-white mb-4 flex items-center gap-2">
                <Server size={14} /> Authentication
              </h3>
              {[['SPF', email.spf], ['DKIM', email.dkim], ['DMARC', email.dmarc]].map(([k, v]) => (
                <div key={k} className="flex justify-between items-center py-2 border-b border-gray-800/50 last:border-0">
                  <span className="text-xs text-gray-500">{k}</span>
                  <Badge v={v} />
                </div>
              ))}
              <div className="mt-4">
                <p className="text-xs text-gray-500 mb-2">Risk factors</p>
                {risk.reasons.length === 0
                  ? <p className="text-xs text-emerald-400">No risk factors detected</p>
                  : risk.reasons.map((r, i) => (
                    <p key={i} className="text-xs text-red-400 flex items-start gap-1.5 mb-1">
                      <span className="mt-0.5">•</span>{r}
                    </p>
                  ))
                }
              </div>
            </div>
          </div>

 {/* URLs */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="text-sm font-medium text-white mb-4 flex items-center gap-2">
              <Globe size={14} /> URLs found ({email.links?.length || 0})
            </h3>
            {!email.links?.length ? (
              <p className="text-xs text-gray-600">No URLs found in this email</p>
            ) : (
              <div className="flex flex-col gap-2">
                {email.links.map((link, i) => {
                  const intelUrl = intel.urls?.find(u => u.url === link || u.url === 'http://' + link)
                  return (
                    <div key={i} className="flex items-center justify-between bg-gray-800/50 rounded-lg px-3 py-2 gap-3">
                      <span className="text-xs text-blue-400 font-mono truncate">{link}</span>
                      <span className={`text-xs font-medium flex-shrink-0 ${
                        intelUrl?.malicious ? 'text-red-400' :
                        intelUrl ? 'text-emerald-400' : 'text-gray-500'}`}>
                        {intelUrl?.malicious ? `Malicious (${intelUrl.detections})` :
                         intelUrl ? 'Clean' : 'Not scanned'}
                      </span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* attachments */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="text-sm font-medium text-white mb-4 flex items-center gap-2">
              <Paperclip size={14} /> Attachments ({email.attachments?.length || 0})
            </h3>
            {!email.attachments?.length ? (
              <p className="text-xs text-gray-600">No attachments found in this email</p>
            ) : (
              <div className="flex flex-col gap-2">
                {email.attachments.map((att, i) => {
                  const intelAtt = intel.attachments?.[i]
                  return (
                    <div key={i} className="bg-gray-800/50 rounded-lg px-3 py-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-gray-300 font-medium">{att.filename || 'Unknown file'}</span>
                        <span className={`text-xs font-medium flex-shrink-0 ml-4 ${
                          intelAtt?.malicious ? 'text-red-400' :
                          intelAtt ? 'text-emerald-400' : 'text-gray-500'}`}>
                          {intelAtt?.malicious ? `Malicious (${intelAtt.detections})` :
                           intelAtt ? 'Clean' : 'Not scanned'}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-xs text-gray-600 font-mono truncate">{att.sha256}</span>
                        <span className="text-xs text-gray-600 flex-shrink-0">{(att.size / 1024).toFixed(1)} KB</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
          {/* attachments */}
          {intel.attachments?.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-medium text-white mb-4 flex items-center gap-2">
                <Paperclip size={14} /> Attachments
              </h3>
              {intel.attachments.map((a, i) => (
                <div key={i} className="flex items-center justify-between bg-gray-800/50 rounded-lg px-3 py-2 mb-2">
                  <span className="text-xs text-gray-400 font-mono truncate">{a.hash}</span>
                  <span className={`text-xs font-medium ml-4 flex-shrink-0 ${a.malicious ? 'text-red-400' : 'text-emerald-400'}`}>
                    {a.malicious ? 'Malicious' : 'Clean'}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* SOC findings */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="text-sm font-medium text-white mb-4">SOC findings</h3>
            {soc.findings.map((f, i) => (
              <p key={i} className="text-xs text-gray-400 flex items-start gap-2 mb-2">
                <span className="text-emerald-400 mt-0.5 flex-shrink-0">→</span>{f}
              </p>
            ))}
          </div>

          {/* recommendations */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="text-sm font-medium text-white mb-4">Recommendations</h3>
            {soc.recommendations.map((r, i) => (
              <p key={i} className="text-xs text-gray-400 flex items-start gap-2 mb-2">
                <span className="text-blue-400 mt-0.5 flex-shrink-0">•</span>{r}
              </p>
            ))}
          </div>

        </div>
      )}
    </div>
  )
}