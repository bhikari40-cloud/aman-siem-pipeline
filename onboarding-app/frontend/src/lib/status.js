import { CheckCircle2, CircleHelp, CircleSlash, TriangleAlert } from 'lucide-react'

// Shared status -> {icon, label, classes} mapping so SiemPicker,
// TransportPicker, and GuidancePanel render identical badges for the same
// underlying siem_catalog status instead of drifting independently.
export const STATUS_META = {
  verified: {
    icon: CheckCircle2,
    label: 'Verified',
    classes: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  },
  untested: {
    icon: CircleHelp,
    label: 'Untested',
    classes: 'bg-amber-50 text-amber-700 border-amber-200',
  },
  vendor_blocked: {
    icon: TriangleAlert,
    label: 'Blocked by vendor',
    classes: 'bg-red-50 text-red-700 border-red-200',
  },
  not_implemented: {
    icon: CircleSlash,
    label: 'Not yet supported',
    classes: 'bg-slate-100 text-slate-500 border-slate-200',
  },
}

// A siem_type's overall picker badge uses its BEST transport's status --
// e.g. wazuh shows "Verified" even though bulk_http alone doesn't produce a
// native alert, because at least one transport (syslog) is fully verified.
// The per-transport nuance still shows up once a transport is selected
// (see TransportPicker/GuidancePanel), this is only for the initial list.
const STATUS_RANK = ['verified', 'untested', 'vendor_blocked', 'not_implemented']

export function bestStatus(siemSpec) {
  const statuses = Object.values(siemSpec.transports)
    .map((t) => t.status)
    .filter(Boolean)
  if (statuses.length === 0) return null
  return statuses.sort((a, b) => STATUS_RANK.indexOf(a) - STATUS_RANK.indexOf(b))[0]
}
