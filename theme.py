from tkinter import ttk
import tkinter as tk

def get_system_font():
    """Get the best available system font"""
    try:
        import platform
        system = platform.system()
        if system == "Darwin":  # macOS
            return "SF Pro Text"
        elif system == "Windows":
            return "Segoe UI"
        else:
            return "DejaVu Sans"
    except:
        return "TkDefaultFont"

class ModernTheme:
    @staticmethod
    def setup_theme():
        # Define colors - macOS Monterey/Ventura inspired
        bg_color = "#1E1E1E"           # Darker background
        secondary_bg = "#2D2D2D"       # Lighter background for containers
        input_bg = "#FFFFFF"           # White background for input/output fields
        accent_color = "#0A84FF"       # Apple blue
        text_color = "#FFFFFF"         # White text for dark backgrounds
        input_text = "#000000"         # Black text for input fields
        border_color = "#3D3D3D"       # Subtle borders
        hover_color = "#0062CC"        # Darker blue for hover states
        
        style = ttk.Style()
        
        # Global styling
        style.configure(".",
            background=bg_color,
            foreground=text_color,
            font=(get_system_font(), 13),
            relief="flat"
        )
        
        # Label styling - more modern and clean
        style.configure("TLabel",
            background=bg_color,
            foreground=text_color,
            padding=(5, 5),
            font=("SF Pro Display", 13)
        )
        
        # Modern macOS-style button
        style.layout("Rounded.TButton",
            [('Button.padding', {'children':
                [('Button.label', {'sticky': 'nswe'})],
                'sticky': 'nswe'})]
        )
        
        style.configure("Rounded.TButton",
            background=accent_color,
            foreground=text_color,
            padding=(15, 8),
            font=("SF Pro Text", 13),
            borderwidth=0,
            relief="flat"
        )
        
        # Add subtle hover animation effect
        style.map("Rounded.TButton",
            background=[
                ("active", hover_color),
                ("pressed", hover_color),
                ("disabled", "#404040")
            ],
            foreground=[("disabled", "#808080")]
        )
        
        # Modern input field styling
        style.configure("Rounded.TEntry",
            padding=(12, 8),
            fieldbackground="#FFFFFF",
            foreground=input_text,
            insertcolor=accent_color,
            borderwidth=0,
            relief="flat",
            font=("SF Pro Text", 13)
        )
        
        # Output field with monospace font
        style.configure("Output.TEntry",
            padding=(12, 8),
            fieldbackground="#FFFFFF",
            foreground=input_text,
            insertcolor=accent_color,
            borderwidth=0,
            relief="flat",
            font=("SF Mono", 15)
        )
        
        # Modern checkbox styling
        style.configure("Rounded.TCheckbutton",
            background=bg_color,
            foreground=text_color,
            font=("SF Pro Text", 13),
            padding=(5, 5)
        )
        
        # Card-like container styling
        style.configure("Card.TFrame",
            background=secondary_bg,
            relief="flat",
            borderwidth=0,
            padding=15
        )
        
        # Modern section headers
        style.configure("Card.TLabelframe",
            background=secondary_bg,
            font=("SF Pro Display", 13),
            relief="flat",
            borderwidth=1,
            bordercolor=border_color,
            padding=20
        )
        
        style.configure("Card.TLabelframe.Label",
            background=secondary_bg,
            foreground=text_color,
            font=("SF Pro Display", 14),
            padding=(10, 5)
        )
        
        # Modern list view styling
        style.configure("Rounded.Treeview",
            background=input_bg,
            foreground=input_text,
            fieldbackground=input_bg,
            font=("SF Pro Text", 13),
            rowheight=30,
            borderwidth=0,
            relief="flat",
            padding=(10, 5)
        )
        
        style.configure("Rounded.Treeview.Heading",
            background="#F5F5F7",
            foreground=input_text,
            font=("SF Pro Display", 13, "bold"),
            relief="flat",
            padding=(10, 8)
        )
        
        # Modern spinbox
        style.configure("Rounded.TSpinbox",
            fieldbackground=input_bg,
            background=input_bg,
            foreground=input_text,
            arrowcolor=input_text,
            padding=(12, 8),
            borderwidth=0,
            relief="flat",
            font=("SF Pro Text", 13)
        )
        
        # Minimal modern scrollbar
        style.layout("Rounded.Vertical.TScrollbar", 
            [('Vertical.Scrollbar.trough',
                {'children':
                    [('Vertical.Scrollbar.thumb', 
                        {'expand': '1', 'sticky': 'nswe'})],
                    'sticky': 'ns'})]
        )
        
        style.configure("Rounded.Vertical.TScrollbar",
            background=bg_color,
            troughcolor="#3D3D3D",
            width=6,
            relief="flat",
            borderwidth=0,
            arrowcolor=text_color
        )
        
        return style 