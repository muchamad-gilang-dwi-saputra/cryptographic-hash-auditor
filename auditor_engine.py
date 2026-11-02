import argparse
import hashlib
import json
import math
import time
from datetime import datetime

import bcrypt
from argon2 import PasswordHasher
from rich.console import Console
from rich.panel import Panel
from rich.progress import track
from rich.table import Table
from rich.text import Text

console = Console()


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


def measure_time(func, *args, iterations=10) -> float:
    """Mengukur rata-rata waktu eksekusi fungsi dalam milidetik."""
    start_time = time.perf_counter()
    for _ in range(iterations):
        func(*args)
    end_time = time.perf_counter()
    return ((end_time - start_time) / iterations) * 1000


def hash_md5(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def hash_bcrypt(password: str, rounds: int = 12) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds))


def hash_argon2(password: str, time_cost: int = 2, memory_cost: int = 102400) -> str:
    ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=8)
    return ph.hash(password)


def auto_tune_bcrypt(password: str, target_ms: float = 250.0) -> int:
    """Mencari cost factor Bcrypt paling optimal untuk CPU lokal."""
    optimal_cost = 10
    for cost in range(10, 16):
        t_ms = measure_time(lambda c=cost: hash_bcrypt(password, rounds=c), iterations=3)
        if t_ms >= target_ms:
            optimal_cost = cost
            break
        optimal_cost = cost
    return optimal_cost


def run_expert_audit(password: str, iterations: int, export_json: bool):
    console.clear()

    # 1. Header UI
    title = Text("🛡️ Enterprise Cryptographic Audit & Auto-Tuning Engine", style="bold cyan", justify="center")
    subtitle = Text("DevSecOps & ISO 27001 Credential Assessment Suite", style="dim", justify="center")
    console.print(Panel.fit(title + Text("\n") + subtitle, border_style="cyan"))

    # 2. Analisis Entropi Password
    entropy_bits = calculate_shannon_entropy(password)
    console.print("\n[bold yellow][*] Memulai Analisis Kredensial Input...[/bold yellow]")
    console.print(f" ├─ Target Password : [bold white]{password}[/bold white]")
    console.print(f" ├─ Panjang String  : [bold white]{len(password)} karakter[/bold white]")
    console.print(f" └─ Shannon Entropy : [bold cyan]{entropy_bits:.2f} bits[/bold cyan]")

    if entropy_bits < 40:
        console.print("    [bold red]⚠️ Status Entropi: Sangat Rentan (Sandi Mudah Ditebak)[/bold red]")
    elif entropy_bits < 70:
        console.print("    [bold yellow]⚠️ Status Entropi: Sedang (Direkomendasikan Tambah Variasi Karakter)[/bold yellow]")
    else:
        console.print("    [bold green]✅ Status Entropi: Sangat Kuat (High Complexity)[/bold green]")

    # 3. Auto-Tuning Engine
    console.print("\n[bold yellow][*] Mengatur Auto-Tuner CPU...[/bold yellow]")
    tuned_cost = auto_tune_bcrypt(password, target_ms=200.0)
    console.print(f" └─ Optimal Bcrypt Cost Factor untuk Hardware ini: [bold green]Rounds = {tuned_cost}[/bold green] (~200ms delay target)")

    # 4. Stress-Test Benchmarking
    algorithms = {
        "MD5 (Legacy)": hash_md5,
        "SHA-256 (Fast)": hash_sha256,
        f"Bcrypt (Tuned Cost={tuned_cost})": lambda p: hash_bcrypt(p, rounds=tuned_cost),
        "Argon2id (RFC 9106)": hash_argon2,
    }

    results = {}
    console.print("\n[bold yellow][*] Memulai Benchmark Algoritma...[/bold yellow]")
    for algo_name, func in track(algorithms.items(), description="[green]Executing Stress-Test..."):
        t_ms = measure_time(func, password, iterations=iterations)
        results[algo_name] = t_ms

    # 5. Tabel Visualisasi Hasil
    table = Table(title="📊 Laporan Audit Ketahanan Kredensial", show_header=True, header_style="bold magenta")
    table.add_column("Algoritma Hashing", style="cyan", width=25)
    table.add_column("Latensi (ms)", justify="right", width=15)
    table.add_column("Resistensi Attack", justify="center", width=25)
    table.add_column("Status ISO 27001", justify="center", width=18)

    export_data = {
        "timestamp": datetime.now().isoformat(),
        "password_metadata": {
            "length": len(password),
            "entropy_bits": round(entropy_bits, 2),
        },
        "auto_tuned_bcrypt_cost": tuned_cost,
        "audit_results": [],
    }

    for algo, t_ms in results.items():
        waktu_str = f"{t_ms:.4f} ms"
        if "MD5" in algo or "SHA" in algo:
            resistensi = "[bold red]Sangat Lemah[/bold red]"
            status = "[red]NON-COMPLIANT[/red]"
            compliance = "FAIL"
        elif "Bcrypt" in algo:
            resistensi = "[bold yellow]Tinggi[/bold yellow]"
            status = "[yellow]COMPLIANT[/yellow]"
            compliance = "PASS"
        else:
            resistensi = "[bold green]Maksimal (ASIC/GPU Resistant)[/bold green]"
            status = "[green]RECOMMENDED[/green]"
            compliance = "EXCELLENT"

        table.add_row(algo, waktu_str, resistensi, status)
        export_data["audit_results"].append({
            "algorithm": algo,
            "latency_ms": round(t_ms, 4),
            "compliance_status": compliance,
        })

    console.print(table)

    # 6. Export Laporan JSON
    if export_json:
        filename = f"audit_report_{int(time.time())}.json"
        with open(filename, "w") as f:
            json.dump(export_data, f, indent=4)
        console.print(f"\n[bold green]📄 Laporan Audit JSON Berhasil Diterbitkan: [white]{filename}[/white][/bold green]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enterprise Cryptographic Security Auditor")
    parser.add_argument("--password", type=str, default="P@ssw0rd_Enterprise_2026!", help="Target password string to test")
    parser.add_argument("--iterations", type=int, default=5, help="Number of test iterations")
    parser.add_argument("--export", action="store_true", help="Export result to JSON audit report")

    args = parser.parse_args()
    run_expert_audit(args.password, args.iterations, args.export)