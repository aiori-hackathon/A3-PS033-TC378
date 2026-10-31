$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$projectPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $projectPython)) { throw 'Create the project virtual environment first.' }
& $projectPython -m PyInstaller --noconfirm --onefile --windowed --name DiagDiscover --icon "$PSScriptRoot\assets\app.ico" --add-data "$PSScriptRoot\web;web" --add-data "$PSScriptRoot\assets;assets" --collect-submodules dns --distpath desktop --workpath .scratch/app-build --specpath .scratch desktop_app.py
if ($LASTEXITCODE -ne 0) { throw 'Application build failed.' }
Write-Output 'Built desktop\DiagDiscover.exe'
