import { STATUS_META, bestStatus } from '../lib/status.js'

// All SUPPORTED_SIEMS are listed here, "not_implemented"/"vendor_blocked"
// entries included -- hiding them would contradict the decision to expose
// every type with honest labeling. They stay selectable so a customer can
// see the roadmap, but the confirm step downstream disables submission for
// them (see OnboardingPage).
export default function SiemPicker({ catalog, selected, onSelect }) {
  const entries = Object.values(catalog)

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      {entries.map((siem) => {
        const status = bestStatus(siem)
        const meta = status ? STATUS_META[status] : null
        const Icon = meta?.icon
        const isSelected = selected === siem.key

        return (
          <button
            key={siem.key}
            type="button"
            onClick={() => onSelect(siem.key)}
            className={`flex items-center justify-between rounded-xl border p-4 text-left transition ${
              isSelected
                ? 'border-indigo-400 bg-indigo-50/60 ring-1 ring-indigo-300'
                : 'border-slate-200 bg-white hover:border-slate-300'
            }`}
          >
            <span className="font-medium text-slate-800">{siem.label}</span>
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
  )
}
