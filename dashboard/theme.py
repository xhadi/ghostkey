"""CSS for the dashboard: brand tokens, bundled brand fonts, and Streamlit chrome overrides.

The fonts are read from dashboard/fonts/ and embedded as base64, so the page works offline
(the decoy network and the demo laptop may have no internet).
"""
from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent
FONTS_DIR = DASHBOARD_DIR / "fonts"
ASSETS_DIR = DASHBOARD_DIR / "assets"
BRAND_DIR = ASSETS_DIR / "ghostkey-brand"
FAVICON_PATH = BRAND_DIR / "favicon" / "favicon-32x32.png"

# Which characters each font file covers (the browser picks the file by the characters on the page).
ARABIC_RANGE = (
    "U+0600-06FF, U+0750-077F, U+0870-0891, U+0897-08E1, U+08E3-08FF, U+200C-200E, U+2010-2011, "
    "U+204F, U+2E41, U+FB50-FDFF, U+FE70-FE74, U+FE76-FEFC"
)
LATIN_RANGE = (
    "U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, "
    "U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD"
)
PLEX_WEIGHTS = (400, 500, 600)


def _data_uri(path: Path, mime: str) -> str:
    return f"data:{mime};base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def _font_face(family: str, weight: int, file_name: str, unicode_range: str) -> str:
    uri = _data_uri(FONTS_DIR / file_name, "font/woff2")
    return (
        f"@font-face{{font-family:'{family}';font-style:normal;font-weight:{weight};"
        f"font-display:swap;src:url({uri}) format('woff2');unicode-range:{unicode_range};}}"
    )


def font_faces() -> str:
    """IBM Plex Sans Arabic (UI text, Arabic + Latin) and Space Grotesk 700 (wordmark only)."""
    faces = []
    for weight in PLEX_WEIGHTS:
        for subset, unicode_range in (("latin", LATIN_RANGE), ("arabic", ARABIC_RANGE)):
            file_name = f"ibm-plex-sans-arabic-{subset}-{weight}.woff2"
            faces.append(_font_face("IBM Plex Sans Arabic", weight, file_name, unicode_range))
    faces.append(_font_face("Space Grotesk", 700, "space-grotesk-latin-700.woff2", LATIN_RANGE))
    return "".join(faces)


@lru_cache(maxsize=1)
def mark_data_uri() -> str:
    """The white brand mark (pixel ghost with key) as a data URI for the header band."""
    return _data_uri(BRAND_DIR / "svg" / "ghostkey-mark-white.svg", "image/svg+xml")


BASE_CSS = """
:root{
  --plum-950:#2A1240; --plum-900:#3A1A52; --plum-700:#54266F; --plum-600:#6B3590;
  --lavender:#E4D3F2; --rule:#E2DAEA; --canvas:#F7F7FA; --white:#FFFFFF;
  --real:#1F6F5C; --alarm:#C8243A; --amber:#B87900; --medium:#8A7A3D;
  --sev-critical:var(--alarm); --sev-high:var(--amber); --sev-medium:var(--medium); --sev-low:var(--plum-600);
  --font:'IBM Plex Sans Arabic',Tahoma,sans-serif;
  --font-name:'Space Grotesk','Inter',Arial,sans-serif;
  --mono:ui-monospace,Consolas,monospace;
  /* the brand mark is built from 10px rounded squares on a 12px grid; echoed here, very faintly */
  --ghost-grid:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12'%3E%3Crect x='1' y='1' width='10' height='10' rx='2' fill='%2354266F' fill-opacity='0.05'/%3E%3C/svg%3E");
}

/* ---- Streamlit chrome: hide it, set page background and font ---- */
#MainMenu,footer,header[data-testid="stHeader"],[data-testid="stToolbar"],[data-testid="stDecoration"],
[data-testid="stStatusWidget"],.stDeployButton,[data-testid="stSidebarCollapsedControl"]{display:none !important;}
.stApp,[data-testid="stAppViewContainer"]{background:var(--canvas);}
.stApp,.stApp p,.stApp button,.stApp input,.stApp label,.stApp summary,.stApp h1,.stApp h2,.stApp h3,.stApp li,.stApp dd,.stApp dt,.stApp td,.stApp th{
  font-family:var(--font); color:var(--plum-950); letter-spacing:0;}
.stApp .block-container{padding:0 0 64px 0 !important; max-width:100% !important;}
.stApp [data-testid="stVerticalBlock"]{gap:0;}
.stApp [data-testid="stMarkdownContainer"] p{margin:0;}
/* streamlit gives every markdown block margin-bottom:-1rem, which makes the block overlap what follows */
.stApp [data-testid="stMarkdownContainer"]{margin-bottom:0 !important;}
.stApp h1,.stApp h2,.stApp h3{padding:0; margin:0; font-weight:500; line-height:1.3;}
.stApp ul,.stApp ol{list-style:none; margin:0; padding:0;}
.stApp ul[class^="gk-"],.stApp ol[class^="gk-"]{padding:0 !important; margin-left:0 !important;}
.stApp ul[class^="gk-"] li,.stApp ol[class^="gk-"] li{margin-left:0 !important; margin-bottom:0 !important;}
.stApp [data-testid="stMarkdownContainer"] ul,.stApp [data-testid="stMarkdownContainer"] ol{padding:0; margin:0;}
/* a fragment rerun marks old elements "stale" and dims them; the dashboard refreshes every 2s, so never dim */
.stApp [data-stale="true"]{opacity:1 !important; transition:none !important;}
.gk-tab-nums,.gk-id,.gk-traffic b,.gk-marker-meta,.gk-n,.gk-pts,.gk-table td,.gk-log small,.gk-chips li{font-variant-numeric:tabular-nums;}

/* ---- header band: the only gradient on the page ---- */
.gk-band{background:radial-gradient(circle at 50% 42%, #54266F 0%, #3A1A52 55%, #2A1240 100%); padding:28px 40px 20px; color:var(--canvas);}
.gk-band-top{display:flex; justify-content:space-between; align-items:flex-start; gap:24px; flex-wrap:wrap;}
.gk-lockup{display:inline-flex; align-items:center; gap:20px; direction:ltr; color:var(--canvas);}
.gk-lockup img{height:48px; width:auto; display:block;}
.gk-lockup .gk-divider{width:1px; height:44px; background:currentColor; opacity:.3;}
.stApp .gk-lockup .gk-name{font-family:var(--font-name); font-weight:700; font-size:28px; letter-spacing:3px; line-height:1; color:var(--canvas);}
.stApp .gk-lockup .gk-tagline{display:block; font-family:var(--font); font-weight:500; font-size:13px; letter-spacing:0; margin-top:6px; opacity:.8; text-align:left;}
.gk-band-side{text-align:right;}
.stApp .gk-subtitle{font-size:15px; color:var(--lavender);}
.stApp .gk-live{font-size:13px; color:var(--lavender); display:flex; align-items:center; justify-content:flex-end; gap:8px; padding-top:6px;}
.gk-live-dot{width:8px; height:8px; border-radius:50%; background:var(--canvas); display:inline-block;}
.gk-traffic{display:flex; flex-wrap:wrap; gap:8px 32px; margin-top:20px !important; padding-top:14px !important; border-top:1px solid rgba(228,211,242,.28);}
.stApp .gk-traffic li{font-size:13px; color:var(--lavender);}
.stApp .gk-traffic b{font-size:18px; font-weight:500; color:var(--canvas); margin-right:4px;}

/* ---- page body ---- */
.st-key-main{padding:32px 40px 0;}
.stApp .st-key-main [data-testid="stHorizontalBlock"]{gap:2rem;}
.stApp .st-key-main [data-testid="stColumn"]{min-width:0;}
.stApp .gk-empty{padding:56px 40px;}
.stApp .gk-empty h1{font-size:24px;}
.stApp .gk-empty p{font-size:15px; color:var(--plum-600); padding:10px 0 14px;}
.stApp .gk-empty code{display:inline-block; font-family:var(--mono); font-size:13px; background:var(--white); border:1px solid var(--rule); border-radius:6px; padding:10px 14px; color:var(--plum-950);}

/* ---- incident rail (st.button rows keyed inc_<id>) ---- */
.stApp [class*="st-key-inc_"]{margin-bottom:10px;}
.stApp [class*="st-key-inc_"] button{width:100%; display:block; text-align:left; height:auto; min-height:0; padding:10px 14px;
  background:transparent; border:1px solid var(--rule); border-left:4px solid var(--sev,var(--rule)); border-radius:6px; box-shadow:none;}
.stApp [class*="st-key-inc_"] button:hover{border-color:var(--plum-600); border-left-color:var(--sev,var(--rule));}
.stApp [class*="st-key-inc_"] button[kind="primary"]{background:var(--white); border-color:var(--plum-700); border-left-color:var(--sev,var(--plum-700));}
.stApp [class*="st-key-inc_"] button>div{display:block; width:100%; text-align:left;}
/* the label paragraphs become a 2-column grid: id | score, then kind, ip and tag across both columns */
.stApp [class*="st-key-inc_"] button [data-testid="stMarkdownContainer"]{display:grid; grid-template-columns:1fr auto; column-gap:12px; row-gap:2px; width:100%;}
.stApp [class*="st-key-inc_"] button p{font-size:13px; color:var(--plum-600); line-height:1.5; margin:0; white-space:normal; font-variant-numeric:tabular-nums; grid-column:1 / -1;}
.stApp [class*="st-key-inc_"] button p:nth-child(1){grid-column:1; font-size:15px; font-weight:500; color:var(--plum-950);}
.stApp [class*="st-key-inc_"] button p:nth-child(2){grid-column:2; text-align:right; font-size:15px; font-weight:500; color:var(--sev,var(--plum-950));}
.stApp [class*="st-key-inc_"] button p:nth-child(5){justify-self:start; margin-top:6px; font-size:13px; font-weight:500; color:var(--amber); background:#F6EBCF; border-radius:3px; padding:1px 8px;}

/* ---- incident header ---- */
.sev-critical{--sev:var(--alarm);} .sev-high{--sev:var(--amber);} .sev-medium{--sev:var(--medium);} .sev-low{--sev:var(--plum-600);}
.stApp .gk-detail-head{border-left:4px solid var(--sev); padding:2px 0 2px 18px; margin-bottom:24px;}
.stApp .gk-id{font-size:13px; color:var(--plum-600);}
.stApp .gk-detail-head h1{font-size:24px; margin:2px 0 12px;}
.gk-facts{display:flex; flex-wrap:wrap; gap:8px 32px;}
.stApp .gk-facts dt{font-size:13px; color:var(--plum-600);}
.stApp .gk-facts dd{font-size:15px; margin:0;}

/* ---- shared section styling ---- */
.stApp .gk-panel{background:var(--white); border:1px solid var(--rule); border-radius:12px; padding:20px 24px; margin-bottom:24px;}
.stApp .gk-panel h2,.stApp .gk-section h2{font-size:18px; margin-bottom:14px;}
.stApp h3{font-size:13px; color:var(--plum-600); margin:16px 0 6px;}
.stApp .gk-quiet,.stApp .gk-none{font-size:13px; color:var(--plum-600);}
.stApp .gk-note{font-size:13px; color:var(--amber); padding-bottom:8px;}

/* ---- stage map ----
   Heads, real plane and decoy plane all use the SAME grid (--cols equal lanes, same side padding),
   so every lane lines up from the headings down through both planes. */
.stApp .gk-section{margin-bottom:24px;}
.gk-map-scroll{overflow-x:auto; padding-bottom:6px;}
.gk-map{--cols:3; min-width:calc(var(--cols) * 230px); position:relative;}
.gk-cols-4{--cols:4;}
.gk-heads,.gk-row{display:grid; grid-template-columns:repeat(var(--cols),minmax(0,1fr));}
.gk-heads{position:relative; margin-bottom:14px;}
.gk-heads::before{content:""; position:absolute; left:14px; right:14px; top:50%; height:2px; background:var(--plum-700);}
.stApp .gk-head{position:relative; padding:0 14px; font-size:15px; font-weight:500;}
.gk-head span{position:relative; background:var(--canvas); padding:2px 12px 2px 0; display:inline-flex; align-items:center; gap:8px;}
.gk-head span::before{content:""; width:10px; height:10px; border-radius:50%; background:var(--plum-700); display:inline-block;}
.gk-plane{padding:12px 0 14px; box-shadow:inset 4px 0 0 var(--plane-accent);}
.gk-plane-real{--plane-accent:var(--real); --lane:rgba(31,111,92,.16); background:var(--white); border:1px solid var(--rule); border-left:0; border-radius:4px 10px 10px 4px;}
.gk-plane-decoy{--plane-accent:var(--plum-700); --lane:rgba(84,38,111,.16); background-color:rgba(228,211,242,.55); background-image:var(--ghost-grid); border-radius:4px 10px 10px 4px;}
.stApp .gk-plane-label{font-size:13px; font-weight:500; padding:0 0 10px 18px;}
.stApp .gk-plane-real .gk-plane-label{color:var(--real);}
.stApp .gk-plane-decoy .gk-plane-label{color:var(--plum-700);}
.gk-plane-empty{display:flex; align-items:baseline; gap:16px; padding:10px 0;}
.stApp .gk-plane-empty .gk-plane-label{padding:0 0 0 18px;}
.stApp .gk-plane-note{font-size:13px; color:var(--plum-600);}
.gk-cell{display:flex; flex-direction:column; gap:8px; min-height:96px; padding:2px 14px 0;}
.gk-cell+.gk-cell{border-left:1px solid var(--lane);}
.gk-gateway{position:relative; height:3px; background:var(--plum-950); margin:18px 0; border-radius:2px;}
.gk-gateway>span{position:absolute; left:16px; top:-11px; background:var(--canvas); padding:0 10px; font-size:13px; font-weight:500; line-height:22px; color:var(--plum-950);}
.gk-gateway:has(.gk-on-line){margin:96px 0;}
.gk-on-line{position:absolute; left:0; right:0; top:50%; transform:translateY(-50%);}

.gk-marker{--accent:var(--plum-700); --from:0px; background:var(--white); border:1px solid var(--rule); border-left:4px solid var(--accent); border-radius:6px; padding:8px 10px;}
.gk-marker-real{--accent:var(--real); --from:18px;}
.gk-marker-decoy{--accent:var(--plum-700); --from:-18px; border-radius:3px;}
.gk-marker-blocked{--accent:var(--alarm);}
.gk-marker.cited{outline:2px solid var(--accent); outline-offset:2px;}
.stApp .gk-marker-head{display:flex; align-items:center; gap:8px; font-size:15px;}
.stApp .gk-marker-head b{font-weight:500;}
.gk-n{display:inline-flex; align-items:center; justify-content:center; min-width:20px; height:20px; border-radius:10px; border:1px solid var(--rule); font-size:13px; color:var(--plum-600);}
.stApp .gk-marker-target{font-size:13px; margin-top:4px; overflow-wrap:anywhere;}
.stApp .gk-marker-meta{display:flex; flex-wrap:wrap; gap:2px 12px; font-size:13px; color:var(--plum-600); margin-top:4px;}
.gk-badges{display:flex; flex-wrap:wrap; gap:4px; margin-top:6px !important;}
.stApp .gk-badges li{font-size:13px; font-weight:500; border-radius:3px; padding:1px 7px;}
.stApp .gk-marker-decoy .gk-badges li{background:var(--lavender); color:var(--plum-700);}
.stApp .gk-marker-real .gk-badges li{background:#DCEEE9; color:var(--real);}
.stApp .gk-marker-blocked .gk-badges li{background:#F6DADF; color:var(--alarm);}
.stApp .gk-legend{font-size:13px; color:var(--plum-600); padding-top:14px;}

/* the one animation: a new event materializes out of the gateway line */
@keyframes gk-materialize{from{opacity:0; transform:translateY(var(--from));} to{opacity:1; transform:none;}}
.gk-marker.fresh{animation:gk-materialize .6s ease-out both;}
@media (prefers-reduced-motion:reduce){.gk-marker.fresh{animation:none;}}

/* ---- score ledger ---- */
.gk-ledger li{display:grid; grid-template-columns:64px 1fr; align-items:baseline; padding:8px 0; border-bottom:1px solid var(--rule);}
.stApp .gk-pts{font-size:24px; font-weight:500; color:var(--plum-700);}
.stApp .gk-rule{font-size:15px; display:block;}
.stApp .gk-rule small{display:block; font-size:13px; color:var(--plum-600); font-variant-numeric:tabular-nums;}
.stApp .gk-total{display:grid; grid-template-columns:64px 1fr; align-items:baseline; padding-top:10px; border-top:2px solid var(--plum-950); margin-top:-1px;}
.stApp .gk-total .gk-pts{color:var(--plum-950);}
.stApp .gk-total-label{font-size:18px; font-weight:500; color:var(--sev);}

/* ---- analyst ---- */
.stApp .gk-source{font-size:13px; font-weight:400; color:var(--plum-700); background:var(--lavender); border-radius:4px; padding:2px 8px; margin-left:10px; vertical-align:middle;}
.stApp .gk-hypothesis{font-size:24px; font-weight:500; padding-bottom:10px;}
.stApp .gk-confidence{font-size:13px; font-weight:400; color:var(--plum-600); margin-left:14px;}
.stApp .gk-ar{direction:rtl; text-align:right; line-height:1.8; font-size:15px; padding:2px 0 6px;}
.stApp .gk-summary{font-size:18px; padding-bottom:12px;}
.gk-three{display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:8px 28px;}
.gk-chips{display:flex; flex-wrap:wrap; gap:6px;}
.stApp .gk-chips li{font-size:13px; background:var(--canvas); border:1px solid var(--rule); border-radius:4px; padding:2px 8px; overflow-wrap:anywhere;}
.gk-alts li{border-top:1px solid var(--rule); padding:8px 0 2px;}
.stApp .gk-alts b{font-size:15px; font-weight:500;}

/* ---- response ---- */
.stApp .gk-ask{font-size:18px; font-weight:500; padding:14px 0 8px;}
.stApp [class*="st-key-approve_"] button,.stApp [class*="st-key-reject_"] button{font-size:15px; padding:6px 22px; border-radius:6px; min-height:0; height:auto;}
.stApp [class*="st-key-approve_"] button{background:var(--plum-700); border:1px solid var(--plum-700);}
.stApp [class*="st-key-approve_"] button p{color:var(--white);}
.stApp [class*="st-key-reject_"] button{background:transparent; border:1px solid var(--rule);}
.stApp [class*="st-key-reject_"] button p{color:var(--plum-600);}
.stApp .st-key-reviewer label p{font-size:13px; color:var(--plum-600);}
.stApp .st-key-reviewer{width:280px !important; max-width:100%; margin-bottom:4px;}
.stApp .st-key-reviewer [data-testid="stTextInput"],.stApp .st-key-reviewer [data-baseweb="input"]{width:100% !important; max-width:280px !important;}
.stApp [class*="st-key-decide_"]{flex-direction:row !important; gap:12px !important; align-items:center;}
.stApp [class*="st-key-decide_"]>div,.stApp [class*="st-key-decide_"] [data-testid="stButton"]{flex:0 0 auto !important; width:max-content !important; min-width:0 !important;}
.stApp [class*="st-key-decide_"]{padding-bottom:12px;}
.stApp .st-key-reviewer [data-baseweb="input"],.stApp .st-key-reviewer [data-baseweb="base-input"]{background:var(--white); border-radius:6px;}
.stApp .st-key-reviewer [data-baseweb="input"]{border:1px solid var(--rule);}
.stApp .st-key-reviewer input{background:var(--white); -webkit-text-fill-color:var(--plum-950);font-size:15px; font-family:var(--font); color:var(--plum-950);}
.gk-log li{display:flex; justify-content:space-between; gap:16px; font-size:13px; color:var(--plum-600); padding:3px 0;}
.stApp .gk-log li small{font-size:13px;}
.stApp .gk-log .gk-decided{color:var(--plum-950);}

/* ---- event log ---- */
.stApp [data-testid="stExpander"]{margin-top:24px;}
.stApp [data-testid="stExpander"] details{background:var(--white); border:1px solid var(--rule); border-radius:8px;}
.stApp [data-testid="stExpander"] summary p{font-size:15px;}
.gk-table-scroll{overflow-x:auto;}
.gk-table{border-collapse:collapse; width:100%;}
.stApp .gk-table th{font-size:13px; font-weight:500; color:var(--plum-600); text-align:left; padding:6px 12px; border-bottom:1px solid var(--rule); white-space:nowrap;}
.stApp .gk-table td{font-size:13px; padding:6px 12px; border-bottom:1px solid var(--rule); white-space:nowrap;}
.stApp .gk-table td.gk-path{font-family:var(--mono);}

/* ---- traffic triage (compact; table rules are scoped so the event log keeps its own spacing) ---- */
.st-key-triage{padding:12px 40px 0;}
.stApp .gk-triage{margin-bottom:12px;}
.stApp .gk-triage h2{font-size:15px; margin-bottom:8px;}
.gk-funnel{display:flex; flex-wrap:wrap; gap:6px 0;}
.stApp .gk-funnel li{position:relative; flex:0 1 auto; display:flex; align-items:baseline; gap:6px; white-space:nowrap; padding:6px 12px 6px 18px; background:var(--white); border:1px solid var(--rule); border-left-width:0;}
.stApp .gk-funnel li:first-child{padding-left:12px; border-left-width:1px; border-radius:8px 0 0 8px;}
.stApp .gk-funnel li:last-child{border-radius:0 8px 8px 0; border-color:var(--plum-700); background:var(--lavender);}
.gk-funnel li+li::before{content:""; position:absolute; left:-1px; top:50%; width:8px; height:8px; margin-top:-4px; border-top:1px solid var(--plum-600); border-right:1px solid var(--plum-600); transform:translateX(-5px) rotate(45deg); background:var(--canvas);}
.stApp .gk-step-count{font-size:18px; font-weight:500; font-variant-numeric:tabular-nums; line-height:1.2;}
.stApp .gk-step-label{font-size:13px; color:var(--plum-950);}
.stApp .gk-step-note{font-size:13px; color:var(--plum-600); font-variant-numeric:tabular-nums;}
.stApp .gk-step-note::before{content:"·"; margin-right:6px;}
.stApp .gk-triage-note{font-size:13px; color:var(--plum-600); padding:6px 0 8px;}
.stApp .gk-triage .gk-quiet{padding-top:2px;}
.stApp .gk-triage .gk-table th,.stApp .gk-triage .gk-table td{padding:3px 10px; font-size:13px;}
.stApp .gk-pill{display:inline-block; font-size:12px; font-weight:500; border-radius:3px; padding:0 6px; background:var(--canvas); color:var(--plum-600); border:1px solid var(--rule);}
.stApp .gk-pill-incident{background:#F6DADF; color:var(--alarm); border-color:transparent;}
.stApp .gk-pill-flagged{background:#F6EBCF; color:var(--amber); border-color:transparent;}
.stApp .gk-pill-normal{background:#DCEEE9; color:var(--real); border-color:transparent;}

@media (max-width:900px){.gk-three{grid-template-columns:1fr;} .gk-band{padding:20px;} .st-key-main{padding:20px;} .st-key-triage{padding:12px 20px 0;} .stApp .gk-funnel li{white-space:normal; border-left-width:1px; border-radius:8px; padding-left:12px; margin-right:6px;} .gk-funnel li+li::before{display:none;}}
"""


@lru_cache(maxsize=1)
def css() -> str:
    """The full <style> block. Built once; the base64 fonts make it large."""
    return f"<style>{font_faces()}{BASE_CSS}</style>"
