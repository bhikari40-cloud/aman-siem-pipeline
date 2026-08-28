import { ShieldAlert } from 'lucide-react'
import { motion } from 'framer-motion'

// Shown whenever GET /api/onboarding/:token 404s -- unknown, expired,
// revoked, or already-used token. No form is rendered at all: this state is
// terminal, a fresh link has to come from whoever set up the integration.
export default function InvalidLinkState() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="mx-auto flex max-w-md flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white p-10 text-center shadow-sm"
    >
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-50 text-red-500">
        <ShieldAlert size={24} />
      </div>
      <h1 className="text-lg font-semibold text-slate-900">This link isn't valid anymore</h1>
      <p className="text-sm leading-relaxed text-slate-500">
        Onboarding links are single-use and expire after a while. If you still need to set up
        your SIEM integration, ask whoever sent you this link for a new one.
      </p>
    </motion.div>
  )
}
