import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Loader2 } from 'lucide-react'

import { ApiError, getOnboardingState, getSiemCatalog, submitOnboarding } from '../lib/api.js'
import InvalidLinkState from '../components/InvalidLinkState.jsx'
import SiemPicker from '../components/SiemPicker.jsx'
import TransportPicker from '../components/TransportPicker.jsx'
import DynamicAuthFields from '../components/DynamicAuthFields.jsx'
import GuidancePanel from '../components/GuidancePanel.jsx'
import ConfirmationView from '../components/ConfirmationView.jsx'

export default function OnboardingPage() {
  const { token } = useParams()

  const [loading, setLoading] = useState(true)
  const [invalid, setInvalid] = useState(false)
  const [catalog, setCatalog] = useState(null)
  const [tenantLabel, setTenantLabel] = useState('')

  const [selectedSiem, setSelectedSiem] = useState(null)
  const [selectedTransport, setSelectedTransport] = useState(null)
  const [fieldValues, setFieldValues] = useState({})
  const [webhookUrl, setWebhookUrl] = useState('')
  const [verifySsl, setVerifySsl] = useState(true)

  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState(null)
  const [saved, setSaved] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const [catalogResult, stateResult] = await Promise.all([
          getSiemCatalog(),
          getOnboardingState(token),
        ])
        if (cancelled) return
        setCatalog(catalogResult)
        setTenantLabel(stateResult.tenant_label)
      } catch (err) {
        if (cancelled) return
        if (err instanceof ApiError && err.status === 404) {
          setInvalid(true)
        } else {
          setInvalid(true) // any other failure to resolve the link is treated the same way
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => {
      cancelled = true
    }
  }, [token])

  const siemSpec = catalog && selectedSiem ? catalog[selectedSiem] : null
  const transport = useMemo(() => {
    if (!siemSpec) return null
    return siemSpec.transports[selectedTransport] || siemSpec.transports[siemSpec.default_transport]
  }, [siemSpec, selectedTransport])

  function handleSelectSiem(key) {
    const spec = catalog[key]
    setSelectedSiem(key)
    setSelectedTransport(spec.default_transport)
    setFieldValues({})
  }

  function handleFieldChange(name, value) {
    setFieldValues((prev) => ({ ...prev, [name]: value }))
  }

  const canSubmit =
    transport &&
    transport.status !== 'not_implemented' &&
    webhookUrl.trim().length > 0 &&
    transport.fields.every((field) => !field.required || (fieldValues[field.name] || '').trim())

  async function handleSubmit(e) {
    e.preventDefault()
    if (!canSubmit) return

    setSubmitting(true)
    setSubmitError(null)
    try {
      const submission = {
        siem_type: selectedSiem,
        transport: transport.key,
        webhook_url: webhookUrl.trim(),
        verify_ssl: transport.url_scheme === 'syslog' ? true : verifySsl,
        ...fieldValues,
      }
      const result = await submitOnboarding(token, submission)
      setSaved(result.saved)
    } catch (err) {
      setSubmitError(err instanceof ApiError ? err.message : 'Something went wrong. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="animate-spin text-slate-400" size={28} />
      </div>
    )
  }

  if (invalid) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 px-4">
        <InvalidLinkState />
      </div>
    )
  }

  if (saved) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 px-4">
        <ConfirmationView saved={saved} />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-50 px-4 py-12">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="mx-auto flex max-w-xl flex-col gap-6"
      >
        <header>
          <p className="text-sm font-medium text-indigo-600">{tenantLabel}</p>
          <h1 className="text-2xl font-semibold text-slate-900">Connect your SIEM</h1>
          <p className="mt-1 text-sm text-slate-500">
            Pick where Aman should send your blocked-DNS alerts. Nothing streams until you save
            this form.
          </p>
        </header>

        <section className="flex flex-col gap-3">
          <h2 className="text-sm font-semibold text-slate-700">1. Choose your SIEM</h2>
          <SiemPicker catalog={catalog} selected={selectedSiem} onSelect={handleSelectSiem} />
        </section>

        {siemSpec && transport && (
          <form onSubmit={handleSubmit} className="flex flex-col gap-5 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <TransportPicker
              siemSpec={siemSpec}
              selected={transport.key}
              onSelect={setSelectedTransport}
            />

            <label className="flex flex-col gap-1 text-sm">
              <span className="font-medium text-slate-700">
                {transport.url_scheme === 'syslog' ? 'Target host:port' : 'Webhook URL'}
                <span className="text-red-500"> *</span>
              </span>
              <input
                type="text"
                required
                placeholder={transport.url_example}
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                className="rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs text-slate-800 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-300"
              />
            </label>

            <DynamicAuthFields fields={transport.fields} values={fieldValues} onChange={handleFieldChange} />

            {transport.url_scheme !== 'syslog' && (
              <label className="flex items-center gap-2 text-sm text-slate-600">
                <input
                  type="checkbox"
                  checked={verifySsl}
                  onChange={(e) => setVerifySsl(e.target.checked)}
                  className="rounded border-slate-300"
                />
                Verify TLS certificate (turn off only for a known self-signed cert)
              </label>
            )}

            <GuidancePanel siemSpec={siemSpec} transport={transport} />

            {submitError && (
              <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{submitError}</p>
            )}

            <button
              type="submit"
              disabled={!canSubmit || submitting}
              className="flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300"
            >
              {submitting && <Loader2 className="animate-spin" size={16} />}
              Save integration
            </button>
          </form>
        )}
      </motion.div>
    </div>
  )
}
