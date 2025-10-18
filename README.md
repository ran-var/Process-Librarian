```
     ███████████                                                                                  
    ░░███░░░░░███                                                                                 
     ░███    ░███ ████████   ██████   ██████   ██████   █████   █████                             
     ░██████████ ░░███░░███ ███░░███ ███░░███ ███░░███ ███░░   ███░░                              
     ░███░░░░░░   ░███ ░░░ ░███ ░███░███ ░░░ ░███████ ░░█████ ░░█████                             
     ░███         ░███     ░███ ░███░███  ███░███░░░   ░░░░███ ░░░░███                            
     █████        █████    ░░██████ ░░██████ ░░██████  ██████  ██████                             
    ░░░░░        ░░░░░      ░░░░░░   ░░░░░░   ░░░░░░  ░░░░░░  ░░░░░░                              
                                                                         
                                                                                                   
              █████        ███  █████                                    ███                      
             ░░███        ░░░  ░░███                                    ░░░                       
              ░███        ████  ░███████  ████████   ██████   ████████  ████   ██████   ████████  
              ░███       ░░███  ░███░░███░░███░░███ ░░░░░███ ░░███░░███░░███  ░░░░░███ ░░███░░███ 
              ░███        ░███  ░███ ░███ ░███ ░░░   ███████  ░███ ░░░  ░███   ███████  ░███ ░███ 
              ░███      █ ░███  ░███ ░███ ░███      ███░░███  ░███      ░███  ███░░███  ░███ ░███ 
              ███████████ █████ ████████  █████    ░░████████ █████     █████░░████████ ████ █████
             ░░░░░░░░░░░ ░░░░░ ░░░░░░░░  ░░░░░      ░░░░░░░░ ░░░░░     ░░░░░  ░░░░░░░░ ░░░░ ░░░░░  
```

usage: `main.exe [options] <argument>`

options:
  -i, --inspect <process_name>    inspect process and display information
  -m, --modules <process_name>    list loaded modules (dlls)
  -t, --threads <process_name>    list all threads
  -l, --list                      list all running processes
  -h, --help                      display this help message

examples:

```
> .\main.exe -i not

process 'not' not found
did you mean:
  - notepad.exe

> .\main.exe -i notepad.exe

notepad.exe
basic
  pid                    26216
  base priority          8
  parent pid             9860 (explorer.exe)
  threads                7
  elevated               no

memory
  working set            14692 kb
  peak working set       14696 kb
  private bytes          3140 kb
  pagefile usage         3140 kb
  peak pagefile          3172 kb
  page faults            3823

i/o counters
  read operations        2
  write operations       0
  other operations       110
  read bytes             16 kb
  write bytes            0 kb
  other bytes            0 kb

handles
  handle count           244
  gdi objects            23
  user objects           27

priority
  priority class         normal
  dep enabled            yes (permanent)

path
  executable             C:\Windows\System32\notepad.exe
  file size              196 kb
 ```