from PyInstaller.utils.hooks import collect_all

# Collect all cryptography dependencies
datas, binaries, hiddenimports = collect_all('cryptography')

# Add them to the bundle
datas.extend(datas)
binaries.extend(binaries)
hiddenimports.extend(hiddenimports) 