import { Info } from 'lucide-react'
import { STATUS_META } from '../lib/status.js'

const NATIVE_ALERTING_LABEL = {
  yes: 'Alerts will show up natively in your SIEM’s own alerting UI.',
  no: 'Data will be delivered, but will NOT appear as a native alert -- you’ll need to build your own detection rule on top of it.',
  vendor_blocked:
    'Native alerting for this path is currently blocked by an issue on the vendor’s side, not ours.',
}

// Placeholder guidance rendering: this project's copywriting review pass
// (see the plan) hasn't authored per-transport prose yet, so this renders
// the catalog's machine-readable facts (status, native_alerting) as plain
// labels rather than inventing marketing/help copy ad hoc. Swap the body
// below for real copy, keyed off `transport.guidance_key`, once that pass
// lands -- the key is already threaded through from the backend for that.
export default function GuidancePanel({ siemSpec, transport }) {
  const meta = transport.status ? STATUS_META[transport.status] : null

  return (
    <div className="flex flex-col gap-2 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600">
      <div className="flex items-center gap-2 font-medium text-slate-700">
        <Info size={16} />
        What entering this does
      </div>
      <p>
        Once saved, alerts Aman blocks for your account start streaming to{' '}
        <span className="font-mono text-xs">{siemSpec.label}</span> over this connection. Nothing
        is sent before you submit this form.
      </p>
      {meta && (
        <p>
          Integration status: <span className="font-medium">{meta.label}</span>
        </p>
      )}
      {transport.native_alerting && (
        <p>{NATIVE_ALERTING_LABEL[transport.native_alerting] || transport.native_alerting}</p>
      )}
      {transport.status === 'not_implemented' && (
        <p className="font-medium text-slate-700">
          This SIEM type isn’t implemented yet -- saving is disabled until it is.
        </p>
      )}
    </div>
  )
}
