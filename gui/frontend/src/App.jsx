import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Upload, History,
  ShieldAlert, BarChart3, Menu, X
} from 'lucide-react'
import { useState } from 'react'
import Dashboard   from './pages/Dashboard'
import Scanner     from './pages/Scanner'
import HistoryPage from './pages/History'
import IOCTracker  from './pages/IOCTracker'
import Analytics   from './pages/Analytics'

const nav = [
  { to: '/',          icon: LayoutDashboard, label: 'Dashboard'   },
  { to: '/scan',      icon: Upload,          label: 'Scan Email'  },
  { to: '/history',   icon: History,         label: 'History'     },
  { to: '/iocs',      icon: ShieldAlert,     label: 'IOC Tracker' },
  { to: '/analytics', icon: BarChart3,       label: 'Analytics'   },
]

export default function App() {
  const [open, setOpen] = useState(true)

  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-950 text-gray-100 overflow-hidden">

        <aside className={`${open ? 'w-56' : 'w-16'} flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col transition-all duration-200`}>
          <div className="flex items-center justify-between px-4 py-4 border-b border-gray-800">
            {open && (
              <div className="flex items-center gap-2">
                <ShieldAlert size={18} className="text-emerald-400" />
                <span className="text-sm font-semibold text-white">PhishGuard AI</span>
              </div>
            )}
            <button onClick={() => setOpen(!open)} className="text-gray-400 hover:text-white ml-auto">
              {open ? <X size={16} /> : <Menu size={16} />}
            </button>
          </div>

          <nav className="flex-1 py-4 flex flex-col gap-1 px-2">
            {nav.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors
                   ${isActive
                     ? 'bg-emerald-500/10 text-emerald-400 font-medium'
                     : 'text-gray-400 hover:text-white hover:bg-gray-800'}`
                }
              >
                <Icon size={16} className="flex-shrink-0" />
                {open && <span>{label}</span>}
              </NavLink>
            ))}
          </nav>

          {open && (
            <div className="px-4 py-3 border-t border-gray-800">
              <p className="text-xs text-gray-600">PhishGuard AI v1.0</p>
            </div>
          )}
        </aside>

        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/"          element={<Dashboard />}   />
            <Route path="/scan"      element={<Scanner />}     />
            <Route path="/history"   element={<HistoryPage />} />
            <Route path="/iocs"      element={<IOCTracker />}  />
            <Route path="/analytics" element={<Analytics />}   />
          </Routes>
        </main>

      </div>
    </BrowserRouter>
  )
}