import hashlib
import json
import math
import time
from datetime import datetime

import bcrypt
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from argon2 import PasswordHasher

# Setup Konfigurasi Halaman Streamlit
st.set_page_config(
    page_title="Mesin Audit Kriptografi | SINTA 3",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling (Dark Theme & Glassmorphism Aesthetic)
st.markdown(
    """
    <style>
    .stApp {
        background-color: #0e1117;
    }
    .metric-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 18px;
        text-align: center;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def calculate_shannon_entropy(password: str) -> float:
    """Menghitung entropi Shannon password dalam satuan bits."""
    if not password:
        return 0.0
    entropy = 0.0
    length = len(password)
    symbols = set(password)
    for symbol in symbols:
        p_x = float(password.count(symbol)) / length
        entropy -= p_x * math.log2(p_x)
    return entropy * length


def measure_time(func, *args, iterations=3) -> float:
    """Mengukur rata-rata latensi eksekusi dalam milidetik."""
    start_time = time.perf_counter()
    for _ in range(iterations):
        func(*args)
    end_time = time.perf_counter()
    return ((end_time - start_time) / iterations) * 1000


def hash_md5(pwd: str) -> str:
    return hashlib.md5(pwd.encode()).hexdigest()


def hash_sha256(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()


def hash_bcrypt(pwd: str, rounds: int) -> bytes:
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=rounds))


def hash_argon2(pwd: str, time_cost: int, memory_cost: int) -> str:
    ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=4)
    return ph.hash(pwd)


# --- HEADER DASHBOARD ---
st.title("Auditor Keamanan Kriptografi Enterprise")
st.caption("Riset Terapan SINTA 3: Evaluasi Interaktif Kekuatan Kredensial & Performa Hashing")
st.divider()

# --- SIDEBAR CONFIGURATION ---
st.sidebar.header("Parameter Mesin")
bcrypt_rounds = st.sidebar.slider("Faktor Biaya Bcrypt (Rounds)", min_value=8, max_value=14, value=11)
argon2_mem = st.sidebar.select_slider(
    "Konsumsi Memori Argon2 (KiB)",
    options=[32768, 65536, 102400],
    value=65536,
    format_func=lambda x: f"{x // 1024} MB",
)
benchmark_iters = st.sidebar.slider("Iterasi Benchmark", min_value=1, max_value=10, value=3)

# --- SECTION 1: ENTROPY ANALYSIS ---
st.subheader("1. Analisis Entropi Kredensial")
col_input, col_gauge = st.columns([1.2, 1])

with col_input:
    target_pwd = st.text_input(
        "Masukkan String Kata Sandi untuk Diuji:",
        value="P@ssw0rd_Enterprise_2026!",
        type="password",
    )

    entropy_bits = calculate_shannon_entropy(target_pwd)

    st.markdown(
        f"""
        <div class="metric-card">
            <h4>Analisis Karakter</h4>
            <p>Panjang String: <b>{len(target_pwd)} Karakter</b></p>
            <p>Nilai Entropi Shannon: <b>{entropy_bits:.2f} Bit</b></p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if entropy_bits < 40:
        st.error("Status: Sangat Rentan (Kompleksitas Rendah / Mudah Ditebak)")
    elif entropy_bits < 70:
        st.warning("Status: Sedang (Kompleksitas Menengah)")
    else:
        st.success("Status: Sangat Kuat (Kompleksitas Entropi Tinggi)")

with col_gauge:
    fig_gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=entropy_bits,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Entropi Shannon (Bit)"},
            gauge={
                "axis": {"range": [0, 120]},
                "bar": {"color": "#00E676"},
                "steps": [
                    {"range": [0, 40], "color": "#FF5252"},
                    {"range": [40, 70], "color": "#FFD600"},
                    {"range": [70, 120], "color": "#1DE9B6"},
                ],
            },
        )
    )
    fig_gauge.update_layout(height=290, margin={"l": 20, "r": 20, "t": 60, "b": 20}, paper_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig_gauge, use_container_width=True)

st.divider()

# --- SECTION 2: HASH BENCHMARKING ---
st.subheader("2. Uji Tekan Latensi Hashing Real-Time")

if st.button("Jalankan Benchmark Kriptografi", type="primary"):
    with st.spinner("Mengeksekusi iterasi uji tekan..."):
        # Run Benchmarks
        t_md5 = measure_time(lambda: hash_md5(target_pwd), iterations=benchmark_iters)
        t_sha256 = measure_time(lambda: hash_sha256(target_pwd), iterations=benchmark_iters)
        t_bcrypt = measure_time(lambda: hash_bcrypt(target_pwd, rounds=bcrypt_rounds), iterations=benchmark_iters)
        t_argon2 = measure_time(lambda: hash_argon2(target_pwd, time_cost=2, memory_cost=argon2_mem), iterations=benchmark_iters)

    # Metric Cards
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("MD5", f"{t_md5:.4f} ms", delta="Rentan", delta_color="inverse")
    m2.metric("SHA-256", f"{t_sha256:.4f} ms", delta="Rentan", delta_color="inverse")
    m3.metric(f"Bcrypt (Cost={bcrypt_rounds})", f"{t_bcrypt:.2f} ms", delta="Patuh")
    m4.metric("Argon2id (RFC 9106)", f"{t_argon2:.2f} ms", delta="Direkomendasikan")

    # Plotly Bar Chart Comparison
    df_results = pd.DataFrame(
        {
            "Algoritma": ["MD5 (Legacy)", "SHA-256 (Fast)", f"Bcrypt (Rounds={bcrypt_rounds})", "Argon2id (RFC 9106)"],
            "Latensi (ms)": [t_md5, t_sha256, t_bcrypt, t_argon2],
            "Status Audit": ["Rentan", "Rentan", "Patuh", "Kelas Enterprise"],
            "Color": ["#FF5252", "#FF5252", "#FFD600", "#00E676"],
        }
    )

    fig_bar = px.bar(
        df_results,
        x="Algoritma",
        y="Latensi (ms)",
        color="Algoritma",
        color_discrete_sequence=["#FF5252", "#FF8A80", "#FFD600", "#00E676"],
        title="Komparasi Latensi (Skala: Milidetik - Latensi Lebih Tinggi Mencegah Serangan Brute-Force)",
        text_auto=".3f",
    )
    fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", showlegend=False)
    st.plotly_chart(fig_bar, use_container_width=True)

    # Compliance Data Table
    st.markdown("### Tabel Kepatuhan Audit ISO 27001")
    st.dataframe(
        df_results[["Algoritma", "Latensi (ms)", "Status Audit"]],
        use_container_width=True,
    )

    # ISO 27001 JSON Export
    audit_payload = {
        "timestamp": datetime.now().isoformat(),
        "password_metadata": {
            "length": len(target_pwd),
            "entropy_bits": round(entropy_bits, 2),
        },
        "engine_parameters": {
            "bcrypt_rounds": bcrypt_rounds,
            "argon2_memory_kib": argon2_mem,
        },
        "audit_results": [
            {"algorithm": "MD5", "latency_ms": round(t_md5, 4), "status": "FAIL"},
            {"algorithm": "SHA-256", "latency_ms": round(t_sha256, 4), "status": "FAIL"},
            {"algorithm": "Bcrypt", "latency_ms": round(t_bcrypt, 4), "status": "PASS"},
            {"algorithm": "Argon2id", "latency_ms": round(t_argon2, 4), "status": "EXCELLENT"},
        ],
    }

    json_data = json.dumps(audit_payload, indent=4)
    st.download_button(
        label="Unduh Laporan Audit JSON ISO 27001",
        data=json_data,
        file_name=f"audit_report_{int(time.time())}.json",
        mime="application/json",
    )