import tkinter as tk
from tkinter import ttk
from network_scanner import scrapScanner

def launch_gui():
    window = tk.Tk()
    window.title("Marc's Network Scanner")
    window.geometry("800x600")

    frm = ttk.Frame(window, padding=10)
    frm.grid()

    
    ttk.Button(frm, text="Quit", command= window.destroy).grid(column=1, row=0)
    
   

    starting_ip = tk.Text(frm, width=20, height=1)
    starting_ip.grid(column=5, row=0)
    starting_ip.insert('1.0', '192.168.1.0/24')



    results_list = tk.Listbox(frm, width=60, height=20)
    results_list.grid(column=1, row=10, columnspan=3, pady=10)

    def run_silent_scan():
        # Clear old results
        results_list.delete(0, tk.END)
        results_list.delete(0, tk.END)
        results_list.insert(0, "Starting Silent Scan")
        results_list.update_idletasks() 
        hosts = scrapScanner.discover_hosts(starting_ip.get('1.0', 'end-1c'))

        # Insert scan results into listbox
        if not hosts:
            results_list.insert(tk.END, "No hosts found, there may be an error in the imput.")
        else:
            for host in hosts:
                results_list.insert(tk.END, host)


    ttk.Button(frm, text="silent Scan", command=run_silent_scan).grid(column=2, row=0)

    def deep_dive():
            # Clear old results
            results_list.delete(0, tk.END)
            results_list.delete(0, tk.END)
            results_list.insert(0, "Starting Deep Dive")
            results_list.update_idletasks() 
            hosts = scrapScanner.get_active_ports(starting_ip.get('1.0', 'end-1c'))

            # Insert scan results into listbox
            if not hosts:
                results_list.insert(tk.END, "No ports found, there may be an error in the imput.")
            else:
                for host in hosts:
                    results_list.insert(tk.END, host)
    ttk.Button(frm, text="Deep Dive", command=deep_dive).grid(column=3, row=0)





    window.mainloop()
