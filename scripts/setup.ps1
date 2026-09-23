# c0mr4de setup - run from a plain PowerShell window inside the repo root.

Write-Host "=== Installing Python dependencies ==="
py -m pip install -r requirements.txt

Write-Host "`n=== Checking Ollama models ==="
$models = ollama list
if ($models -notmatch "qwen2.5-coder") {
    Write-Host "Pulling qwen2.5-coder:7b (local tool-calling model, ~4.7GB)..."
    ollama pull qwen2.5-coder:7b
}
if ($models -notmatch "nomic-embed-text") {
    Write-Host "Pulling nomic-embed-text (embeddings)..."
    ollama pull nomic-embed-text
}

Write-Host "`n=== Setting up config ==="
if (-not (Test-Path "config\config.yaml")) {
    Copy-Item "config\config.example.yaml" "config\config.yaml"
    Write-Host "Created config\config.yaml from the example (defaults to local Ollama). Edit it to switch backends."
}

Write-Host "`n=== Ingesting knowledge (Obsidian vault + playbooks) ==="
py -m c0mr4de.memory.ingest

Write-Host "`n=== Done. Try: py -m c0mr4de.cli run "'"'"recon example.com and summarize the attack surface"'"'" ==="
