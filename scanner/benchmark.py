import time
import argparse
import asyncio
from typing import List
import httpx
from rich.console import Console
from rich.table import Table

from scanner.crawler import AsyncEndpointCrawler, STATIC_WORDLIST

console = Console()


def run_sequential_crawl(base_url: str, wordlist: List[str], timeout: float = 5.0) -> float:
    """Runs a baseline sequential synchronous scan."""
    start = time.perf_counter()
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        for path in wordlist:
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            try:
                client.get(url)
            except httpx.RequestError:
                pass
    return time.perf_counter() - start


async def run_async_crawl(base_url: str, wordlist: List[str], concurrency: int = 10, timeout: float = 5.0) -> float:
    """Runs an asynchronous bounded scan."""
    crawler = AsyncEndpointCrawler(base_url=base_url, concurrency=concurrency, timeout=timeout)
    start = time.perf_counter()
    await crawler.run_crawl(wordlist=wordlist)
    return time.perf_counter() - start


def run_benchmark(target: str, concurrency: int = 10):
    wordlist = STATIC_WORDLIST * 2  # 28 requests for measurable variance
    console.print(f"[bold cyan][*] Running Throughput Benchmark against {target}[/bold cyan]")
    console.print(f"[*] Total Endpoints: {len(wordlist)} | Concurrency: {concurrency}\n")

    # 1. Sequential Benchmark
    console.print("[yellow]Phase 1: Measuring Sequential Enumeration Baseline...[/yellow]")
    seq_time = run_sequential_crawl(target, wordlist)
    seq_rps = round(len(wordlist) / seq_time, 2)
    console.print(f"  Sequential Time: {seq_time:.2f}s ({seq_rps} req/sec)\n")

    # 2. Async Benchmark
    console.print("[green]Phase 2: Measuring Asynchronous Event-Loop Crawler...[/green]")
    async_time = asyncio.run(run_async_crawl(target, wordlist, concurrency=concurrency))
    async_rps = round(len(wordlist) / async_time, 2)
    console.print(f"  Async Time: {async_time:.2f}s ({async_rps} req/sec)\n")

    # Calculation
    delta_pct = round(((seq_time - async_time) / seq_time) * 100, 1)
    speedup = round(seq_time / async_time, 2)

    table = Table(title="Directory Enumeration Concurrency Benchmark", show_header=True)
    table.add_column("Strategy", style="cyan")
    table.add_column("Concurrency", justify="center")
    table.add_column("Elapsed Time (s)", justify="right")
    table.add_column("Throughput (req/s)", justify="right")
    table.add_column("Speedup Delta", style="bold green", justify="right")

    table.add_row("Sequential Baseline", "1", f"{seq_time:.2f}", f"{seq_rps}", "Baseline (0%)")
    table.add_row("Async Event-Loop", str(concurrency), f"{async_time:.2f}", f"{async_rps}", f"+{delta_pct}% ({speedup}x)")

    console.print(table)
    return {
        "sequential_s": seq_time,
        "async_s": async_time,
        "speedup_delta_pct": delta_pct,
        "speedup_ratio": speedup,
    }


def main():
    parser = argparse.ArgumentParser(description="Directory Crawler Concurrency Benchmark Harness")
    parser.add_argument("target", help="Target URL (e.g. https://httpbin.org or https://example.com)")
    parser.add_argument("--concurrency", type=int, default=10, help="Async concurrency level (default: 10)")
    args = parser.parse_args()
    run_benchmark(args.target, concurrency=args.concurrency)


if __name__ == "__main__":
    main()