# -*- coding: utf-8 -*-
"""Pop a native OS file dialog (Open or Save) and print the chosen path to stdout.

Run as a short-lived subprocess by the Flask server so the dialog appears on the
user's desktop without the web server's threads touching Tcl/Tk (not thread-safe).

Usage:   python file_dialog.py <mode> <kind> [suggested_name]
  mode:  open | save
  kind:  pcap | docx
Prints:  the chosen absolute path, or an empty string if the user cancelled.
"""
import sys


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'save'
    kind = sys.argv[2] if len(sys.argv) > 2 else 'docx'
    suggested = sys.argv[3] if len(sys.argv) > 3 else ''

    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        sys.stdout.write('')
        return

    if kind == 'pcap':
        filetypes = [('Packet captures', '*.pcap *.pcapng *.cap'), ('All files', '*.*')]
        defext = '.pcap'
    else:
        filetypes = [('Word Document', '*.docx'), ('All files', '*.*')]
        defext = '.docx'

    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)   # bring dialog to the foreground on Windows
    root.update()

    if mode == 'open':
        path = filedialog.askopenfilename(
            parent=root,
            title='Open Capture File',
            filetypes=filetypes,
        )
    else:
        path = filedialog.asksaveasfilename(
            parent=root,
            title='Save As',
            initialfile=suggested,
            defaultextension=defext,
            filetypes=filetypes,
        )

    try:
        root.destroy()
    except Exception:
        pass

    sys.stdout.write(path or '')


if __name__ == '__main__':
    main()
