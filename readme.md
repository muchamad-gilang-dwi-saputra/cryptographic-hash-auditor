Enterprise Cryptographic Hash Benchmark & Security Auditor (Expert Edition)Aplikasi Command Line Interface (CLI) berstandar industri untuk menguji ketahanan kredensial, menghitung entropi matematis, dan melakukan auto-tuning performa algoritma kriptografi. Proyek ini merupakan implementasi terapan dari Riset Akademik Terakreditasi SINTA 3 untuk mengevaluasi dan mengamankan arsitektur penyimpanan kata sandi pada sistem skala besar.(Letakkan tangkapan layar terminal hasil eksekusi auditor Anda di sini)🚀 Fitur Unggulan (Enterprise Grade)Analisis Entropi Shannon ($H(X)$): Menghitung tingkat keacakan dan kekuatan informasi kata sandi secara matematis sebelum proses hashing dilakukan.Dynamic CPU Auto-Tuning Engine: Mengalkulasi cost factor (Bcrypt rounds) secara otomatis berdasarkan kapasitas komputasi CPU server target untuk mencapai latensi ideal (~200–250 ms).Multi-Algorithm Stress-Test: Membandingkan performa latensi dan resistensi serangan brute-force secara real-time antara MD5, SHA-256, Bcrypt, dan Argon2id (RFC 9106).ISO 27001 JSON Audit Exporter: Menerbitkan dokumen audit keamanan terstruktur berformat JSON yang kompatibel dengan alur CI/CD Pipeline dan sistem pelaporan DevSecOps/SOC.📊 Hasil Benchmark & Analisis Ketahanan (SINTA 3 Findings)Algoritma HashingLatensi (ms)Resistensi AttackStatus ISO 27001Catatan Keamanan AuditorMD5 (Legacy)~0.0035 msSangat LemahNON-COMPLIANTTerlalu cepat, tanpa salt, sangat rentan Rainbow Table & GPU Brute-force.SHA-256 (Fast)~0.0114 msSangat LemahNON-COMPLIANTDirancang untuk kecepatan, tidak aman untuk enkripsi kata sandi pengguna.Bcrypt (Auto-Tuned)~200.00 msTinggiCOMPLIANTMemiliki mekanisme Key Stretching dan Salt otomatis yang efektif.Argon2id (RFC 9106)~36.00 msMaksimalRECOMMENDEDPemenang Password Hashing Competition, tahan serangan hardware khusus (ASIC/GPU).🛠️ Tech Stack & ModulLanguage: Python 3.12 (Core Logic, Math & High-Precision Timers)Cryptographic Engines: bcrypt, argon2-cffiCLI UX/UI: rich (Console, Tables, Progress Bar)Standard Libraries: hashlib, math, argparse, json⚙️ Panduan Instalasi & Eksekusi1. Persiapan EnvironmentClone repositori ini dan instal semua dependensi yang dibutuhkan:git clone https://github.com/USERNAME_ANDA/crypto-audit-suite.git
cd crypto-audit-suite
py -3.12 -m pip install bcrypt argon2-cffi rich tabulate

2. Mode EksekusiPengujian Standar (Default Parameter):py -3.12 auditor_engine.py

Pengujian Kredensial Kustom + Ekspor Laporan ISO 27001 (JSON):py -3.12 auditor_engine.py --password "S4ng4t_Ku4t_&_R4h4s14_2026!" --export

📄 Struktur Keluaran Laporan Audit JSONKetika opsi --export digunakan, sistem akan menghasilkan laporan audit terstruktur seperti berikut:{
    "timestamp": "2026-11-02T21:00:00.000000",
    "password_metadata": {
        "length": 27,
        "entropy_bits": 88.42
    },
    "auto_tuned_bcrypt_cost": 12,
    "audit_results": [
        {
            "algorithm": "Argon2id (RFC 9106)",
            "latency_ms": 36.3682,
            "compliance_status": "EXCELLENT"
        }
    ]
}

Author: Muchamad Gilang Dwi Saputra