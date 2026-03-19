# MCP-FOR-SOC v6.0.0 - Windows Kurulum Rehberi

## 📋 Gereksinimler

### Python Paketleri (pip ile)
```powershell
pip install oletools python-magic-bin pefile yara-python requests
```

> **Not:** Windows'ta `python-magic-bin` kullanın (`python-magic` değil)

---

## 🔧 Harici Araç Kurulumları

### 1. Mandiant capa (Capability Detection)

**İndirme:**
- https://github.com/mandiant/capa/releases
- `capa-vX.X.X-windows.zip` dosyasını indir

**Kurulum:**
```powershell
# ZIP'i çıkar ve PATH'e ekle
Expand-Archive capa-v7.0.1-windows.zip -DestinationPath C:\Tools\capa
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\capa", "User")

# Test
capa --version
```

---

### 2. Mandiant FLOSS (Obfuscated String Extraction)

**İndirme:**
- https://github.com/mandiant/flare-floss/releases
- `floss-vX.X.X-windows.zip` dosyasını indir

**Kurulum:**
```powershell
Expand-Archive floss-v3.1.0-windows.zip -DestinationPath C:\Tools\floss
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\floss", "User")

# Test
floss --version
```

---

### 3. Detect It Easy (DIE) - Packer/Compiler Detection

**İndirme:**
- https://github.com/horsicq/DIE-engine/releases
- `die_win64_portable_X.XX.zip` dosyasını indir

**Kurulum:**
```powershell
Expand-Archive die_win64_portable_3.09.zip -DestinationPath C:\Tools\die
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\die", "User")

# Test (CLI versiyonu)
diec --version
```

---

### 4. binwalk (Firmware/Embedded Analysis)

**Seçenek A - WSL ile (Önerilen):**
```powershell
# WSL kurulu ise
wsl sudo apt install binwalk
```

**Seçenek B - Native Windows:**
```powershell
pip install binwalk
```

> **Not:** Windows native binwalk bazı özellikleri desteklemeyebilir. Kritik firmware analizi için WSL önerilir.

---

### 5. Didier Stevens PDF Tools

**İndirme:**
- https://github.com/DidierStevens/DidierStevensSuite

**Kurulum:**
```powershell
# Git clone veya ZIP indir
git clone https://github.com/DidierStevens/DidierStevensSuite.git C:\Tools\DidierStevens

# PATH'e ekle
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\DidierStevens", "User")

# Kullanım
python C:\Tools\DidierStevens\pdfid.py sample.pdf
python C:\Tools\DidierStevens\pdf-parser.py sample.pdf
```

---

### 6. Sysinternals Strings (Microsoft)

**İndirme:**
- https://docs.microsoft.com/en-us/sysinternals/downloads/strings

**Kurulum:**
```powershell
# İndir ve çıkar
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Strings.zip" -OutFile Strings.zip
Expand-Archive Strings.zip -DestinationPath C:\Tools\Sysinternals
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\Sysinternals", "User")

# Test
strings64 -accepteula
```

---

## 📁 Önerilen Dizin Yapısı

```
C:\Tools\
├── capa\
│   └── capa.exe
├── floss\
│   └── floss.exe
├── die\
│   ├── diec.exe
│   └── die.exe (GUI)
├── DidierStevens\
│   ├── pdfid.py
│   └── pdf-parser.py
└── Sysinternals\
    └── strings64.exe
```

---

## ⚙️ PATH Yapılandırması (Tek Seferde)

```powershell
# Tüm araçları PATH'e ekle
$newPaths = @(
    "C:\Tools\capa",
    "C:\Tools\floss", 
    "C:\Tools\die",
    "C:\Tools\DidierStevens",
    "C:\Tools\Sysinternals"
)

$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
$newPath = $currentPath + ";" + ($newPaths -join ";")
[Environment]::SetEnvironmentVariable("Path", $newPath, "User")

# Yeni terminal aç ve test et
```

---

## ✅ Kurulum Doğrulama

```powershell
# Test script
Write-Host "=== MCP-FOR-SOC v6.0 Tool Check ===" -ForegroundColor Cyan

$tools = @{
    "capa" = "capa --version"
    "floss" = "floss --version"
    "diec" = "diec --version"
    "strings" = "strings64 -accepteula 2>&1 | Select-Object -First 1"
    "pdfid" = "python -c `"import sys; sys.path.insert(0,'C:\\Tools\\DidierStevens'); import pdfid; print('OK')`""
}

foreach ($tool in $tools.Keys) {
    try {
        $result = Invoke-Expression $tools[$tool] 2>&1
        Write-Host "[OK] $tool" -ForegroundColor Green
    } catch {
        Write-Host "[MISSING] $tool" -ForegroundColor Red
    }
}
```

---

## 🐍 Python Entegrasyonu

MCP-FOR-SOC otomatik olarak PATH'teki araçları bulur. Manuel yapılandırma için:

```python
# config.py veya environment variable
import os

# Windows tool paths (opsiyonel override)
os.environ['CAPA_PATH'] = r'C:\Tools\capa\capa.exe'
os.environ['FLOSS_PATH'] = r'C:\Tools\floss\floss.exe'
os.environ['DIEC_PATH'] = r'C:\Tools\die\diec.exe'
```

---

## ⚠️ Bilinen Windows Sorunları

| Araç | Sorun | Çözüm |
|------|-------|-------|
| binwalk | Bazı extraction özellikleri çalışmaz | WSL kullan |
| FLOSS | Uzun sürebilir (5-10 dk) | Timeout artır |
| capa | Büyük dosyalarda yavaş | --format json kullan |
| strings | EULA kabul gerekli | -accepteula flag |

---

## 📦 Hızlı Başlangıç (Chocolatey ile)

```powershell
# Chocolatey kurulu ise
choco install sysinternals -y
choco install python -y
pip install oletools pefile yara-python python-magic-bin

# Manuel kurulum gereken araçlar
# capa, floss, die - GitHub releases'dan indir
```

---

## 🔗 İndirme Linkleri (Direkt)

| Araç | Link |
|------|------|
| capa | https://github.com/mandiant/capa/releases/latest |
| FLOSS | https://github.com/mandiant/flare-floss/releases/latest |
| DIE | https://github.com/horsicq/DIE-engine/releases/latest |
| Strings | https://download.sysinternals.com/files/Strings.zip |
| PDF Tools | https://github.com/DidierStevens/DidierStevensSuite |
