// Renders whatever auth fields the selected transport's catalog entry
// declares. Wazuh's bulk_http is the one case with two fields (username +
// password) instead of one opaque token -- everything else is a single
// field, and the syslog transports declare none at all (no auth exists).
export default function DynamicAuthFields({ fields, values, onChange }) {
  if (fields.length === 0) {
    return (
      <p className="text-sm text-slate-500">
        This transport has no authentication -- the network path itself is the only access
        control.
      </p>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      {fields.map((field) => (
        <label key={field.name} className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-slate-700">
            {field.label}
            {field.required && <span className="text-red-500"> *</span>}
          </span>
          <input
            type={field.kind === 'password' ? 'password' : 'text'}
            required={field.required}
            value={values[field.name] || ''}
            onChange={(e) => onChange(field.name, e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-slate-800 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-300"
            autoComplete="off"
          />
        </label>
      ))}
    </div>
  )
}
