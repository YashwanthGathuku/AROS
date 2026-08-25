# Prepend Python 3.14 and Podman for this PowerShell session.
$py = "C:\Users\Gathu\AppData\Local\Programs\Python\Python314"
$podman = "C:\Users\Gathu\AppData\Local\Programs\Podman"
$env:PY_PYTHON = "3.14"
$env:PATH = "$py\Scripts;$py;$podman;" + $env:PATH
python --version
podman --version
