import { Navigate, Route, Routes } from 'react-router-dom'
import OnboardingPage from './pages/OnboardingPage.jsx'

export default function App() {
  return (
    <Routes>
      <Route path="/onboard/:token" element={<OnboardingPage />} />
      <Route path="*" element={<Navigate to="/onboard/invalid" replace />} />
    </Routes>
  )
}
