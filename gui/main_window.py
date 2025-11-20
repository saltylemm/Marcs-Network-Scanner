import tkinter as tk
from tkinter import ttk

def launch_gui():
    window = tk.Tk()
    window.title("Network Scanner")
    window.geometry("800x600")

    frm = ttk.Frame(window, padding=10)
    frm.grid()

    ttk.Label(frm, text="Hello World!").grid(column=0, row=0)
    ttk.Button(frm, text="Quit", command=window.destroy).grid(column=1, row=0)

    window.mainloop()