import { CheckCircle2 } from 'lucide-react'
import { motion } from 'framer-motion'

// Renders the POST response, which is already public_config()-shaped on the
// backend (auth_token redacted to "********" before it ever reaches here) --
// this component has no raw credential to accidentally echo back.
export default function ConfirmationView({ saved }) {
  const rows = [
    ['SIEM type', saved.siem_type],
    ['Webhook / target', saved.webhook_url],
    ['Auth token', saved.auth_token],
    ['Verify SSL', saved.verify_ssl ? 'Yes' : 'No'],
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="mx-auto flex max-w-md flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm"
    >
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-50 text-emerald-600">
        <CheckCircle2 size={24} />
      </div>
      <h1 className="text-lg font-semibold text-slate-900">Integration saved</h1>
      <p className="text-sm text-slate-500">
        Alerts will start streaming to this destination the next time the pipeline picks up
        your configuration.
      </p>
      <dl className="mt-2 w-full divide-y divide-slate-100 rounded-lg border border-slate-100 text-left text-sm">
        {rows.map(([label, value]) => (
          <div key={label} className="flex justify-between gap-4 px-4 py-2">
            <dt className="text-slate-500">{label}</dt>
            <dd className="truncate font-mono text-xs text-slate-800">{value}</dd>
          </div>
        ))}
      </dl>
    </motion.div>
  )
}
