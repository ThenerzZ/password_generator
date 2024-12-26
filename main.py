#!/usr/bin/env python3
from password_generator import PasswordGenerator

def main():
    try:
        app = PasswordGenerator()
        app.run()
    except Exception as e:
        print(f"Error starting application: {e}")

if __name__ == "__main__":
    main() 