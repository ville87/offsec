# TMUX notes


tmux new-session -s sessionname   
tmux a → attach   

in the tmux session:
```
ctrl + b → d → detach
ctrl + b → % → Split screen vertical
ctrl + b → " → split screen horizontal
ctrl + b → <arrows> → change screen
ctrl + b → c → new tab
ctrl + b → 0 → go to tab 0
```

scrolling back in output:   
ctrl + b → Alt Gr [ → use arrows for up/down   

copying selection   
ctrl + b → Alt Gr [ → move to beginning of text to select   
ctrl + space (starts text selection) → move to end of text to copy   
alt + w   
to insert the copied stuff → ctrl + b ]    

zooming   
zoom into the window where you want to copy output: ctrl + b → z   
go back to "split view": ctrl + b → z (or arrows)   
