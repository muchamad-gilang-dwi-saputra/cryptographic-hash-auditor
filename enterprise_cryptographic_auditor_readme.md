# Enterprise Cryptographic Hash Benchmark & Security Auditor (Expert Edition)

Aplikasi *Command Line Interface* (CLI) untuk menguji ketahanan kredensial, menghitung entropi matematis, dan melakukan *auto-tuning* performa algoritma kriptografi. Proyek ini merupakan implementasi terapan dari **Riset Akademik Terakreditasi SINTA 3** untuk mengevaluasi dan mengamankan arsitektur penyimpanan kata sandi pada sistem skala besar.

*(Letakkan tangkapan layar terminal hasil eksekusi auditor Anda di sini)*

## Fitur Unggulan (Enterprise Grade)

1. **Analisis Entropi Shannon (**$H(X)$**):** Menghitung tingkat keacakan dan kekuatan informasi kata sandi secara matematis sebelum proses *hashing* dilakukan.

2. **Dynamic CPU Auto-Tuning Engine:** Mengalkulasi *cost factor* (Bcrypt *rounds*) secara otomatis berdasarkan kapasitas komputasi CPU server target untuk mencapai latensi ideal (\~200–250 ms).

3. **Multi-Algorithm Stress-Test:** Membandingkan performa latensi dan resistensi serangan *brute-force* secara *real-time* antara MD5, SHA-256, Bcrypt, dan Argon2id (RFC 9106).

4. **ISO 27001 JSON Audit Exporter:** Menerbitkan dokumen audit keamanan terstruktur berformat JSON yang kompatibel dengan alur *CI/CD Pipeline* dan sistem pelaporan *DevSecOps/SOC*.

## Hasil Benchmark & Analisis Ketahanan (SINTA 3 Findings)

| Algoritma Hashing | Latensi (ms) | Resistensi Attack | Status ISO 27001 | Catatan Keamanan Auditor | 
| ----- | ----- | ----- | ----- | ----- | 
| **MD5 (Legacy)** | \~0.0035 ms | Sangat Lemah | `NON-COMPLIANT` | Terlalu cepat, tanpa *salt*, sangat rentan *Rainbow Table* & *GPU Brute-force*. | 
| **SHA-256 (Fast)** | \~0.0114 ms | Sangat Lemah | `NON-COMPLIANT` | Dirancang untuk kecepatan, tidak aman untuk enkripsi kata sandi pengguna. | 
| **Bcrypt (Auto-Tuned)** | \~200.00 ms | Tinggi | `COMPLIANT` | Memiliki mekanisme *Key Stretching* dan *Salt* otomatis yang efektif. | 
| **Argon2id (RFC 9106)** | \~36.00 ms | Maksimal | `RECOMMENDED` | Pemenang *Password Hashing Competition*, tahan serangan hardware khusus (ASIC/GPU). | 

## Tech Stack & Modul

* **Language:** Python 3.12 (Core Logic, Math & High-Precision Timers)

* **Cryptographic Engines:** `bcrypt`, `argon2-cffi`

* **CLI UX/UI:** `rich` (Console, Tables, Progress Bar)

* **Standard Libraries:** `hashlib`, `math`, `argparse`, `json`

## Panduan Instalasi & Eksekusi

### 1. Persiapan Environment

Clone repositori ini dan instal semua dependensi yang dibutuhkan:

```
git clone https://github.com/muchamad-gilang-dwi-saputra/cryptographic-hash-auditor.git
cd crypto-audit-suite
py -3.12 -m pip install bcrypt argon2-cffi rich tabulate

```

### 2. Mode Eksekusi

* **Pengujian Standar (Default Parameter):**

  ```
  py -3.12 auditor_engine.py
  
  ```

* **Pengujian Kredensial Kustom + Ekspor Laporan ISO 27001 (JSON):**

  ```
  py -3.12 auditor_engine.py --password "S4ng4t_Ku4t_&_R4h4s14_2026!" --export
  
  ```

## Struktur Keluaran Laporan Audit JSON

Ketika opsi `--export` digunakan, sistem akan menghasilkan laporan audit terstruktur seperti berikut:

```
{
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

```

**Author:** Muchamad Gilang Dwi Saputra