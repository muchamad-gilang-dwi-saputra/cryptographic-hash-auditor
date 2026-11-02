# Enterprise Cryptographic Hash Benchmark & Security Auditor (Dual-Mode Edition)

Aplikasi audit keamanan kriptografi berstandar industri yang mendukung **Command Line Interface (CLI)** dan **Interactive Web Dashboard (Streamlit)** untuk menguji ketahanan kredensial, menghitung entropi Shannon, serta menguji latensi eksekusi algoritma *hashing*. 

Proyek ini merupakan implementasi terapan dari **Riset Akademik Terakreditasi SINTA 3** untuk mengevaluasi dan mengamankan arsitektur penyimpanan kata sandi pada skala *Enterprise*.

---

## Fitur Utama

- **Arsitektur Dual-Mode:**
  - **CLI Engine (`auditor_engine.py`):** Dirancang untuk integrasi alur DevSecOps, eksekusi di lingkungan server, dan analisis otomatis via argumen terminal (`argparse`).
  - **Web Dashboard (`app.py`):** Antarmuka interaktif berbasis Streamlit dan Plotly untuk demonstrasi *Executive Reporting* dan analisis visual *real-time*.
- **Analisis Entropi Shannon ($H(X)$):** Mengalkulasi tingkat keacakan dan kompleksitas kata sandi secara matematis sebelum proses *hashing* dengan visualisasi *Gauge Chart*.
- **Dynamic CPU Auto-Tuning Engine:** Menghitung *cost factor* (Bcrypt *rounds*) secara otomatis berdasarkan kapasitas komputasi CPU lokal untuk mencapai target latensi ideal (~200–250 ms).
- **Multi-Algorithm Stress-Test:** Membandingkan performa latensi dan resistensi serangan *brute-force* secara *real-time* antara MD5, SHA-256, Bcrypt, dan Argon2id (RFC 9106).
- **ISO 27001 JSON Audit Exporter:** Menerbitkan laporan audit keamanan terstruktur berformat JSON untuk arsip audit dan integrasi sistem SOC/CI-CD Pipeline.

---

## 📊 Hasil Benchmark & Analisis Ketahanan (SINTA 3 Findings)

| Algoritma Hashing | Latensi (ms) | Resistensi Attack | Status ISO 27001 | Catatan Keamanan Auditor |
| :--- | :---: | :---: | :---: | :--- |
| **MD5 (Legacy)** | ~0.0035 ms | Sangat Lemah | NON-COMPLIANT | Terlalu cepat, tanpa *salt*, sangat rentan *Rainbow Table* & GPU *Brute-force*. |
| **SHA-256 (Fast)** | ~0.0114 ms | Sangat Lemah | NON-COMPLIANT | Dirancang untuk kecepatan *throughput*, tidak aman untuk kredensial kata sandi. |
| **Bcrypt (Auto-Tuned)** | ~200.00 ms | Tinggi | COMPLIANT | Memiliki mekanisme *Key Stretching* dan *Salt* otomatis yang efektif menahan laju serangan. |
| **Argon2id (RFC 9106)** | ~36.00 ms | Maksimal | RECOMMENDED | Pemenang *Password Hashing Competition*, tahan serangan *hardware* khusus (ASIC/GPU). |

---

## Tech Stack & Modul

- **Bahasa Pemrograman:** Python 3.12 (Core Logic, Math & High-Precision Timers)
- **Engine Kriptografi:** `bcrypt`, `argon2-cffi`, `hashlib`
- **Antarmuka CLI:** `rich` (Console, Tables, Progress Bar), `argparse`
- **Antarmuka Web Dashboard:** `streamlit`, `plotly`, `pandas`

---

## Panduan Instalasi & Eksekusi

### 1. Persiapan Environment
Clone repositori ini dan instal semua dependensi yang dibutuhkan:
```bash
git clone [https://github.com/muchamad-gilang-dwi-saputra/cryptographic-hash-auditor.git](https://github.com/muchamad-gilang-dwi-saputra/cryptographic-hash-auditor.git)
cd cryptographic-hash-auditor
py -3.12 -m pip install bcrypt argon2-cffi rich tabulate streamlit plotly pandas
2. Mode Eksekusi CLI Engine
Pengujian Standar (Default Parameter):

Bash
py -3.12 auditor_engine.py
Pengujian Kredensial Kustom + Ekspor Laporan ISO 27001 (JSON):

Bash
py -3.12 auditor_engine.py --password "S4ng4t_Ku4t_&_R4h4s14_2026!" --export
3. Mode Eksekusi Interactive Web Dashboard
Jalankan aplikasi web Streamlit:

Bash
py -3.12 -m streamlit run app.py
Aplikasi akan otomatis terbuka di browser pada alamat http://localhost:8501.

Author: Muchamad Gilang Dwi Saputra
