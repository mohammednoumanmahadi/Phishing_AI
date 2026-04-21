import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000
})

export const getStats       = ()         => api.get('/stats')
export const getAllScans     = ()         => api.get('/scans')
export const getScanById    = (id)       => api.get(`/scan/${id}`)
export const getIOCs        = ()         => api.get('/iocs')
export const scanEmail      = (formData) => api.post('/scan', formData)
export const generateReport = (id)       => api.post(`/report/${id}`)
export const downloadPDF    = (id)       => api.get(`/pdf/${id}`, { responseType: 'blob' })

export default api