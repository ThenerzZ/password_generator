import os
import sys
import site

def get_site_packages():
    """Get the site-packages directory containing the DLLs"""
    if hasattr(sys, 'real_prefix'):  # For virtualenv
        return os.path.join(sys.real_prefix, 'Lib', 'site-packages')
    return site.getsitepackages()[0]

def setup_dlls():
    """Ensure DLLs are properly loaded"""
    if sys.platform.startswith('win'):
        # Add site-packages to PATH for DLL loading
        os.environ['PATH'] = get_site_packages() + os.pathsep + os.environ.get('PATH', '')

setup_dlls() 