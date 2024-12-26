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
        '--add-data=theme.py:.',
        '--clean',
        '--noconsole',
    ])

if __name__ == "__main__":
    build() 