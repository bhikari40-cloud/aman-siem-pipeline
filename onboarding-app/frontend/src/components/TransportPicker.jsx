import { STATUS_META } from '../lib/status.js'

// Only rendered when the chosen siem has >1 transport (wazuh, graylog) --
// same siem_type, genuinely different wire behavior and native-alerting
// outcome per transport, so this can't be collapsed into one status badge.
export default function TransportPicker({ siemSpec, selected, onSelect }) {
  const transports = Object.values(siemSpec.transports)
  if (transports.length <= 1) return null

  return (
    <div className="flex flex-col gap-2">
      <span className="text-sm font-medium text-slate-700">How should {siemSpec.label} receive this?</span>
      <div className="flex flex-col gap-2">
        {transports.map((transport) => {
          const meta = transport.status ? STATUS_META[transport.status] : null
          const Icon = meta?.icon
          const isSelected = selected === transport.key

          return (
            <button
              key={transport.key}
              type="button"
              onClick={() => onSelect(transport.key)}
              className={`flex items-center justify-between rounded-lg border p-3 text-left text-sm transition ${
                isSelected
                  ? 'border-indigo-400 bg-indigo-50/60 ring-1 ring-indigo-300'
                  : 'border-slate-200 bg-white hover:border-slate-300'
              }`}
            >
              <span className="font-mono text-xs text-slate-600">{transport.key}</span>
              {meta && (
                <span
                  className={`flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${meta.classes}`}
                >
                  <Icon size={12} />
                  {meta.label}
                </span>
              )}
            </button>
          )
        })}
      </div>
    </div>
  )
}
