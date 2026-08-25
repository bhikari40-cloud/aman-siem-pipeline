"""Streamlit control-plane UI for configuring SIEM webhook delivery.

CONTROL PLANE / USERFLOW
========================
This screen only reads and writes integration configuration. It never touches
the security log stream -- the background Data Plane (orchestrator.py) does the
filtering, enrichment, and delivery. The "Test Run" tab re-uses that exact
pipeline logic with network traffic disabled.
"""

from __future__ import annotations

import json
from html import escape

import streamlit as st

from config_store import (
    ConfigError,
    load_tenant_configs,
    public_config,
    save_tenant_config,
)
from data_generator import generate_opensearch_logs
from ingest import DEFAULT_EXPORT_CSV, iter_export_csv
from orchestrator import run_pipeline


SIEM_OPTIONS = {
    "Splunk (HEC)": "splunk",
    "Microsoft Sentinel": "sentinel",
    "Elastic": "elastic",
    "Datadog": "datadog",
    "Sumo Logic": "sumologic",
    "CrowdStrike Falcon LogScale": "crowdstrike",
    "Generic / Custom Webhook": "generic",
}

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#d97706",
    "Medium": "#0284c7",
    "Low": "#64748b",
}


def label_for_siem(siem_type: str) -> str:
    """Return the UI label for a stored SIEM key."""
    for label, value in SIEM_OPTIONS.items():
        if value == siem_type:
            return label
    return "Generic / Custom Webhook"


# ---------------------------------------------------------------------------
# Design system
# ---------------------------------------------------------------------------

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, .stApp {
  font-family: 'Inter', -apple-system, 'Segoe UI', sans-serif;
}
.stApp { background-color: #f8fafc; color: #0f172a; }

#MainMenu, footer { visibility: hidden; }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stToolbar"] { visibility: hidden; }

.block-container { padding-top: 2.25rem; padding-bottom: 4rem; max-width: 1080px; }

[data-testid="stSidebar"] > div:first-child {
  background: #ffffff;
  border-right: 1px solid #e2e8f0;
}
[data-testid="stSidebar"] .block-container { padding-top: 1.75rem; max-width: none; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid #e2e8f0; }
.stTabs [data-baseweb="tab"] {
  height: 46px; padding: 0 20px; font-size: 14px; font-weight: 500;
  color: #64748b; background: transparent;
}
.stTabs [data-baseweb="tab"]:hover { color: #0f172a; }
.stTabs [aria-selected="true"] { color: #0f172a; }
.stTabs [data-baseweb="tab-highlight"] { background-color: #4f46e5; height: 2px; }

/* Buttons */
.stButton > button, [data-testid="stFormSubmitButton"] > button {
  border-radius: 8px; font-weight: 600; font-size: 14px; padding: 0.6rem 1.1rem;
  border: 1px solid #e2e8f0; background: #ffffff; color: #0f172a;
  transition: background .15s ease, border-color .15s ease, color .15s ease;
}
.stButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover {
  border-color: #c7d2fe; color: #4f46e5;
}
.stButton > button[kind="primary"], [data-testid="stFormSubmitButton"] > button[kind="primary"] {
  background: #4f46e5; border-color: #4f46e5; color: #ffffff;
}
.stButton > button[kind="primary"]:hover,
[data-testid="stFormSubmitButton"] > button[kind="primary"]:hover {
  background: #4338ca; border-color: #4338ca; color: #ffffff;
}

/* Inputs */
[data-testid="stTextInput"] label p,
[data-testid="stSelectbox"] label p,
[data-testid="stSlider"] label p,
[data-testid="stNumberInput"] label p {
  font-size: 13px; font-weight: 500; color: #475569;
}
[data-baseweb="input"], [data-testid="stSelectbox"] [data-baseweb="base-input"] {
  border: 1px solid #e2e8f0 !important; border-radius: 8px !important; background: #ffffff;
}
[data-baseweb="input"]:focus-within,
[data-testid="stSelectbox"] [data-baseweb="base-input"]:focus-within {
  border-color: #4f46e5 !important;
  box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.12) !important;
}

/* Cards (st.container border=True) */
[data-testid="stVerticalBlockBorderWrapper"] {
  background: #ffffff;
  border: 1px solid #e2e8f0 !important;
  border-radius: 12px;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
}

/* Expanders */
[data-testid="stExpander"] {
  border: 1px solid #e2e8f0; border-radius: 10px; background: #ffffff;
}
[data-testid="stExpander"] summary { font-weight: 500; color: #0f172a; }

/* Toast */
[data-testid="stToast"] {
  background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px;
  box-shadow: 0 8px 24px rgba(15, 23, 42, 0.10); font-family: 'Inter', sans-serif;
}

/* Custom components */
.eyebrow {
  font-size: 11px; letter-spacing: .14em; text-transform: uppercase;
  font-weight: 600; color: #64748b;
}
.brand-title { font-size: 40px; font-weight: 800; letter-spacing: -0.02em; color: #0f172a; margin: 0; }
.brand-sub { font-size: 15px; line-height: 1.65; color: #64748b; max-width: 640px; margin: 12px 0 0; }
.rule { height: 1px; background: #e2e8f0; margin: 30px 0 22px; }

.section-lead { font-size: 14px; color: #64748b; line-height: 1.6; margin: -4px 0 18px; }
.section-gap { margin-top: 30px; }

.side-brand { display: flex; align-items: center; gap: 12px; margin-bottom: 30px; }
.brand-mark {
  width: 34px; height: 34px; border-radius: 9px; background: #4f46e5; color: #ffffff;
  font-weight: 800; font-size: 18px; display: flex; align-items: center; justify-content: center;
}
.side-name { font-weight: 700; font-size: 15px; color: #0f172a; }
.side-tag { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: #94a3b8; }
.side-meta { font-size: 13px; color: #64748b; line-height: 1.55; margin: 12px 0 4px; }

.pill {
  display: inline-flex; align-items: center; gap: 8px; background: #ffffff;
  border: 1px solid #e2e8f0; border-radius: 999px; padding: 6px 14px;
  font-size: 13px; font-weight: 500; color: #0f172a;
}
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot-ok { background: #16a34a; }
.dot-off { background: #94a3b8; }

.status-strip { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 2px 0 6px; }
.strip-note { font-size: 13px; color: #64748b; }

.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }
.metric-block {
  background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px;
}
.metric-label { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: #94a3b8; font-weight: 600; }
.metric-value { font-size: 32px; font-weight: 700; color: #0f172a; margin-top: 6px; letter-spacing: -0.01em; }
.metric-hint { font-size: 12px; color: #64748b; margin-top: 2px; }

.attempt { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.sev { display: inline-flex; align-items: center; gap: 7px; font-weight: 600; font-size: 13px; }
.sev-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.meta { font-size: 13px; color: #64748b; }
.domain { font-size: 13px; font-weight: 600; color: #0f172a; }
.attempt-url { font-size: 12px; color: #94a3b8; margin-top: 8px; font-family: ui-monospace, 'SF Mono', monospace; }

.empty-note {
  background: #ffffff; border: 1px dashed #cbd5e1; border-radius: 10px;
  padding: 24px; color: #64748b; font-size: 14px; text-align: center;
}
</style>
"""


def sev_badge(severity: str) -> str:
    """HTML severity indicator: colored dot + label (no filled card)."""
    color = SEVERITY_COLORS.get(severity, "#64748b")
    return f'<span class="sev" style="color:{color}"><span class="sev-dot" style="background:{color}"></span>{escape(severity)}</span>'


def pill(state: str, text: str) -> str:
    """HTML status pill with a small dot."""
    dot_class = "dot-ok" if state == "ok" else "dot-off"
    return f'<span class="pill"><span class="dot {dot_class}"></span>{escape(text)}</span>'


def metric_block(label: str, value: object, hint: str) -> str:
    """Maze-style metric: eyebrow label, large number, hint line."""
    return (
        f'<div class="metric-block">'
        f'<div class="metric-label">{escape(label)}</div>'
        f'<div class="metric-value">{escape(str(value))}</div>'
        f'<div class="metric-hint">{escape(hint)}</div>'
        f"</div>"
    )


def render_sidebar_brand() -> None:
    st.html(
        """
        <div class="side-brand">
          <div class="brand-mark">A</div>
          <div>
            <div class="side-name">IntelliBron Aman</div>
            <div class="side-tag">SIEM Delivery</div>
          </div>
        </div>
        """
    )


def render_header() -> None:
    st.html(
        """
        <div class="eyebrow">Control Plane</div>
        <h1 class="brand-title">IntelliBron Aman</h1>
        <p class="brand-sub">
          Configure customer SIEM webhook delivery. The background pipeline
          filters, enriches, and pushes alerts — this screen only touches
          configuration.
        </p>
        <div class="rule"></div>
        """
    )


def render_status_strip(configs: dict[str, dict[str, str]]) -> None:
    if not configs:
        st.html('<div class="status-strip"><span class="strip-note">No integrations enabled yet — configure one below.</span></div>')
        return

    pills_html = "".join(
        pill("ok", f"{escape(tenant_id)} · {escape(label_for_siem(cfg['siem_type']))}")
        for tenant_id, cfg in configs.items()
    )
    st.html(
        f'<div class="status-strip"><span class="strip-note">Integrations enabled:</span>{pills_html}'
        f'<span class="pill"><span class="dot dot-ok"></span>Fire &amp; Forget active</span></div>'
    )


def render_sidebar_context(
    configs: dict[str, dict[str, str]],
) -> tuple[str, dict[str, str] | None]:
    st.html('<div class="eyebrow">Tenant Context</div>')
    tenant_id = st.text_input(
        "Simulated tenant ID",
        value="tenant-123",
        help="In production this comes from the authenticated user session.",
    ).strip()

    active_config = configs.get(tenant_id)
    if active_config:
        st.html(pill("ok", "Integration configured"))
        st.html(
            f'<div class="side-meta">{escape(label_for_siem(active_config["siem_type"]))}<br>'
            f'{escape(active_config["webhook_url"])}</div>'
        )
        st.json(public_config(active_config))
    else:
        st.html(pill("off", "No integration configured"))
        st.html('<div class="side-meta">Set one up in the Configure tab.</div>')

    return tenant_id, active_config


def render_configure_tab(tenant_id: str, active_config: dict[str, str] | None) -> None:
    st.html('<div class="eyebrow">Integration Settings</div>')
    st.html(
        '<p class="section-lead">Choose a target, provide its webhook endpoint, '
        "and enable the stream. The background pipeline reads this at delivery time.</p>"
    )

    with st.container(border=True):
        default_label = label_for_siem(active_config["siem_type"]) if active_config else "Splunk (HEC)"

        with st.form("integration-form"):
            selected_siem = st.selectbox(
                "Target SIEM platform",
                list(SIEM_OPTIONS.keys()),
                index=list(SIEM_OPTIONS.keys()).index(default_label),
            )
            webhook_url = st.text_input(
                "Destination webhook URL",
                value=active_config["webhook_url"] if active_config else "http://httpbin.org/post",
            )
            auth_token = st.text_input(
                "Authorization token / API key",
                value=active_config["auth_token"] if active_config else "",
                type="password",
                help="Stored only in this local POC config file.",
            )
            submitted = st.form_submit_button("Save & Enable Stream", type="primary")

    if submitted:
        try:
            save_tenant_config(
                {
                    "tenant_id": tenant_id,
                    "siem_type": SIEM_OPTIONS[selected_siem],
                    "webhook_url": webhook_url,
                    "auth_token": auth_token,
                }
            )
        except ConfigError as exc:
            st.toast(f"Couldn't save: {exc}")
        else:
            st.toast(f"{selected_siem} enabled for {tenant_id}.")


def render_test_tab() -> None:
    st.html('<div class="eyebrow">Pipeline Test</div>')
    st.html(
        '<p class="section-lead">Run the same normalization, filtering, tenant isolation, '
        "enrichment, and SIEM formatting logic — no network traffic is sent.</p>"
    )

    source_options = {
        "Synthetic stream": "synthetic",
        "Real export — Aug 21, 2026 (871 events)": "real",
    }

    control_source, control_count, control_run = st.columns([2, 2, 1])
    with control_source:
        data_source = st.selectbox("Data source", list(source_options.keys()))
    with control_count:
        event_count = st.slider("Events to process", min_value=5, max_value=100, value=20, step=5)
    with control_run:
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
        run_clicked = st.button("Run dry test", type="primary", use_container_width=True)

    if source_options[data_source] == "real":
        st.caption("Sample snapshot: 871 events · 100 blocked · 7 tenants. Configure a real subscriber ID (from Stored Config) to see it deliver.")

    if not run_clicked:
        return

    if source_options[data_source] == "real":
        events = iter_export_csv(DEFAULT_EXPORT_CSV, limit=event_count)
    else:
        events = generate_opensearch_logs(event_count)

    result = run_pipeline(
        tenant_configs=load_tenant_configs(),
        events=events,
        send=False,
    )

    metrics = (
        metric_block("Generated", result.generated, "raw events from stream")
        + metric_block("Delivered", result.delivered, "blocked alerts for enabled tenants")
        + metric_block("Failed", result.failed, "webhook errors")
        + metric_block("Tenant drops", result.dropped_unknown_tenant, "subscriber not in config")
        + metric_block("Unblocked drops", result.dropped_unblocked, "benign noise filtered")
    )
    st.html(f'<div class="metrics section-gap">{metrics}</div>')

    if not result.attempts:
        st.html('<div class="empty-note section-gap">No eligible blocked alerts for configured tenants.</div>')
        return

    st.html('<div class="eyebrow section-gap">Delivery Attempts</div>')
    for attempt in result.attempts:
        with st.container(border=True):
            st.html(
                '<div class="attempt">'
                + sev_badge(attempt.severity)
                + f'<span class="meta">{escape(attempt.tenant_id)}</span>'
                + f'<span class="meta">{escape(attempt.siem_type)}</span>'
                + f'<span class="domain">{escape(attempt.domain)}</span>'
                + "</div>"
                + f'<div class="attempt-url">{escape(attempt.webhook_url)}</div>'
            )
            st.json({"headers": attempt.redacted_headers, "payload": attempt.payload})


def render_data_tab() -> None:
    st.html('<div class="eyebrow">Mock Config Database</div>')
    st.html(
        '<p class="section-lead">What the background pipeline reads at delivery time. '
        "Auth tokens are redacted in this view.</p>"
    )

    configs = load_tenant_configs()
    if not configs:
        st.html('<div class="empty-note">No integrations yet. Configure one in the first tab.</div>')
        return

    for tenant_id, cfg in configs.items():
        with st.container(border=True):
            st.html(
                '<div class="attempt">'
                + f'<span class="domain">{escape(tenant_id)}</span>'
                + f'<span class="meta">{escape(label_for_siem(cfg["siem_type"]))}</span>'
                + pill("ok", "Enabled")
                + "</div>"
            )
            st.json(public_config(cfg))


def main() -> None:
    st.set_page_config(
        page_title="IntelliBron Aman — SIEM Delivery",
        page_icon="shield",
        layout="wide",
    )
    st.html(CSS)

    configs = load_tenant_configs()

    with st.sidebar:
        render_sidebar_brand()
        tenant_id, active_config = render_sidebar_context(configs)

    render_header()
    render_status_strip(configs)

    config_tab, test_tab, data_tab = st.tabs(["Configure", "Test Run", "Stored Config"])

    with config_tab:
        render_configure_tab(tenant_id, active_config)

    with test_tab:
        render_test_tab()

    with data_tab:
        render_data_tab()


if __name__ == "__main__":
    main()
