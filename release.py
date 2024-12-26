import os
import subprocess
import platform
import shutil
import sys

def create_release():
    # 1. Clean the project
    print("Cleaning project...")
    subprocess.run([sys.executable, "clean.py"])
    
    # 2. Build executable
    print("Building executable...")
    subprocess.run([sys.executable, "build.py"])
    
    # 3. Create release directory
    release_dir = "release"
    if not os.path.exists(release_dir):
        os.makedirs(release_dir)
    
    # 4. Copy necessary files to release directory
    files_to_copy = [
        "README.md",
        "LICENSE",
        f"dist/Password Manager{'.exe' if platform.system() == 'Windows' else ''}"
    ]
    
    for file in files_to_copy:
        if os.path.exists(file):
            dest = os.path.join(release_dir, os.path.basename(file))
            try:
                shutil.copy2(file, dest)
                print(f"Copied: {file} -> {dest}")
            except Exception as e:
                print(f"Error copying {file}: {e}")
    
    print("Release created successfully!")

if __name__ == "__main__":
    create_release() 