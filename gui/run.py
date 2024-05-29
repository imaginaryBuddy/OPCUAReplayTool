from tkinter import *
import os 
import ipaddress 
import subprocess 
import sys 
import signal
import time
import logging

'''
Example configurations: 
"C:/opcua_tool_shenhwei/pcap_captures/xingyu_opcua_packets.pcap"
"opc.tcp://192.168.1.30:4840"
"192.168.1.111"
snippet start: 31 
snippet end: None 
"0W;0D;3H;30M;0S;"


Example: short test 
"C:/opcua_tool_shenhwei/pcap_captures/short_test_2.pcap"
192.168.1.30
192.168.1.111
snippet start: 8
snippet end: None 
0W;0D;0H;1M;0S;
'''

logging.basicConfig(level=logging.DEBUG, filename="logfiles/all_logs.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)
handler = logging.FileHandler("logfiles/run.log")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

def isValidPath(path: str):
    if os.path.exists(path):
        status.configure(text="Path exists")
        return True 
    else:
        status.configure(text="Invalid Path", fg="red")
        return False 

def isValidIP(ip: str):
    try:
        ip_obj = ipaddress.ip_address(ip)
        print(f"valid ip {ip_obj}")
        return True 
    except:
        print(f"invalid ip {ip}")
        return False 

def getLoopingTime():
    pass 

def run(path: str, server_ip: str, computer_ip: str):
    logger.debug("run")
    status.configure(text="")
    try:
        if isValidPath(path) and isValidIP(server_ip) and isValidIP(computer_ip):
            global p1
            # os.system(f'python gui/run_program.py {path} {server_ip} {computer_ip}')
            print(loop_enabled.get())
            if not loop_enabled.get():
                p1 = subprocess.Popen([sys.executable, "gui/run_program.py", path, server_ip, computer_ip])
                time.sleep(3)

            else: 
                # check that all fields in the loop configuration is valid. 
                try:
                    week_int=int(week.get())
                    day_int=int(day.get())
                    hour_int=int(hour.get())
                    min_int=int(minute.get())
                    sec_int=int(second.get())
                    looping_string=f"{week_int}W;{day_int}D;{hour_int}H;{min_int}M;{sec_int}S;"
                    print(looping_string)
                    starting_ind=str(int(starting_index.get())) # int is just to check that it's an int 
                    ending_ind=ending_index.get() 

                    p1 = subprocess.Popen([sys.executable, "gui/run_program.py", path, server_ip, computer_ip, looping_string, starting_ind, ending_ind])
                    time.sleep(3)
                except Exception as e:
                    print(e)
                    raise 
            
            pathInput.config(state="disabled")
            serverIP.config(state="disabled")
            clientIP.config(state="disabled")

        else:
            print("check on invalid inputs")
    except:
        print("[gui run] Exception reached")
        raise 

def stop():
    logger.debug("Killing process")
    # p1.send_signal(signal.SIGINT)
    # p1.send_signal(signal.SIGTERM)
    p1.send_signal(signal.CTRL_C_EVENT)
    time.sleep(1)
    p1.send_signal(signal.CTRL_C_EVENT)
    p1.send_signal(signal.SIGTERM)
    p1.wait(timeout=10)
    p1.kill()
    pathInput.configure(state="normal")
    serverIP.configure(state="normal")
    clientIP.configure(state="normal")

def enable(children):
   for child in children:
      child.configure(state="normal")

def disable(children):
    for child in children:
        child.configure(state="disabled")

def enable_loop():
    if loop_enabled.get(): # disable
        enable(loop_config_frame.winfo_children())
    else: #enable
        disable(loop_config_frame.winfo_children())


if __name__ == "__main__":
    root = Tk()
    root.geometry("850x400")
    root.title("OPCUA Network Replay Tool")

    frame = Frame(root)
    frame.pack()
    frame.place(relx="0.5", rely="0.5", anchor="c")

    ro=1 
    label=Label(frame, text="OPCUA Network Replay Tool", anchor="c", justify=CENTER).grid(row=ro, pady=3, columnspan=4)

    ro=2
    status=Label(frame, text="", anchor="c", justify=CENTER)
    status.grid(row=ro, columnspan=4)

    ro=3
    label=Label(frame, text="WireShark file capture path:", anchor="c", justify=CENTER).grid(row=ro, column=1, pady=3, columnspan=1)
    pathInput=Entry(frame, width=20, state="normal")
    pathInput.grid(row=ro, column=2, pady=3, columnspan=3)

    ro=4
    label=Label(frame, text="server ip address:", anchor="c", justify=CENTER).grid(row=ro, column=1, pady=3)
    l1=Label(frame, text="opc.tcp://").grid(row=ro, column=2, pady=3)
    serverIP=Entry(frame, width=20, state="normal")
    serverIP.grid(row=ro, column=3, pady=3)
    l2=Label(frame, text=":4840", anchor="c").grid(row=ro, column=4, pady=3)

    ro=5
    label=Label(frame, text="client/computer ip address:", anchor="c", justify=CENTER).grid(row=ro, column=1, pady=3, columnspan=1)
    clientIP=Entry(frame, width=20, state="normal")
    clientIP.grid(row=ro, column=2, pady=3, columnspan=3)

    ro=6
    loop_enabled = BooleanVar()
    loop_enable_button=Checkbutton(frame, text="Looping", variable=loop_enabled, onvalue=True, offvalue=False, command=enable_loop)
    loop_enable_button.grid(row=ro)
    
    ro=7
    # loop configurations
    loop_config_frame = LabelFrame(frame, text="Looping Configurations", padx=4, pady=4)
    loop_config_frame.grid(row=ro, columnspan=4)
    # loop_config_frame.place(relx="0.5")

    # start index of loop packet 
    label=Label(loop_config_frame, text="starting index of loop packet (0th-index):", justify="left").grid(row=1, column=1, columnspan=7)
    starting_index=Entry(loop_config_frame, width=5)
    starting_index.insert(0, "0")
    starting_index.grid(row=1, column=8, columnspan=5)

    # end index of loop packet 
    label=Label(loop_config_frame, text="ending index of loop, 'None' if till the end:", justify="left").grid(row=2, column=1, columnspan=7)
    ending_index=Entry(loop_config_frame, width=5)
    ending_index.insert(0, "None")
    ending_index.grid(row=2, column=8, columnspan=5)
    
    label=Label(loop_config_frame, text="looping time:", anchor="c", justify="left").grid(row=3, column=1, pady=3, columnspan=2)

    # week 
    week=Entry(loop_config_frame, width=3)
    week.insert(0, "0")
    week.grid(padx=0, row=3, column=3)
    label=Label(loop_config_frame, text="W ").grid(padx=0, row=3, column=4)

    # day
    day=Entry(loop_config_frame, width=3)
    day.insert(0, "0")
    day.grid(padx=0, row=3, column=5)
    label=Label(loop_config_frame, text="D ").grid(padx=0, row=3, column=6)

    # hour
    hour=Entry(loop_config_frame, width=3)
    hour.insert(0, "0")
    hour.grid(padx=0, row=3, column=7)
    label=Label(loop_config_frame, text="H ").grid(padx=0, row=3, column=8)

    # minute
    minute=Entry(loop_config_frame, width=3)
    minute.insert(0, "0")
    minute.grid(padx=0, row=3, column=9)
    label=Label(loop_config_frame, text="M ").grid(padx=0, row=3, column=10)

    # second
    second=Entry(loop_config_frame, width=3)
    second.insert(0, "0")
    second.grid(padx=0, row=3, column=11)
    label=Label(loop_config_frame, text="S ").grid(padx=0, row=3, column=12)

    disable(loop_config_frame.winfo_children())


    ro=8
    runButton=Button(frame, text="Run", pady=4, width=4, justify=CENTER, command=lambda: run(pathInput.get(), serverIP.get(),  clientIP.get()), anchor="c").grid(row=ro, columnspan=12, pady=4)

    ro=9
    stopButton=Button(frame, text="Stop", pady=4, width=4, bg="tomato", fg="snow", anchor="c", justify=CENTER, command=stop).grid(row=ro, columnspan=12, pady=4)



    root.mainloop()

