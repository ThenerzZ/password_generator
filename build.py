import PyInstaller.__main__
import platform
import os

def build():
    # Determine the icon file based on the operating system
    if platform.system() == "Windows":
        icon = "assets/icon.ico"
    else:
        icon = "assets/icon.icns"

    PyInstaller.__main__.run([
        'main.py',
        '--name=Password Manager',
        '--onefile',
        '--windowed',
        f'--icon={icon}',
        '--add-data=theme.py;.',
        '--clean',
        '--noconsole',
        # Add required DLLs and dependencies
        '--hidden-import=cryptography',
        '--hidden-import=PIL',
        '--hidden-import=tkinter',
        # Add runtime hooks
        '--runtime-hook=hooks.py',
        # Add additional options for better Windows compatibility
        '--win-private-assemblies',
        '--win-no-prefer-redirects',
    ])

if __name__ == "__main__":
    build() 