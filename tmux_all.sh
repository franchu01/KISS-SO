#!/bin/sh
cd "$(dirname "$0")"

# Matar la sesion vieja
tmux kill-session -t tp

# Crear sesion
tmux new-session -d -s tp './vexec memoria'

# Mouse
tmux setw -g mouse on
# Para tmux < 1.6:
tmux set-option -g prefix C-A
tmux set-option -ga update-environment ' CCC'
# Split windows with easier shortcuts: | and -
tmux unbind %
tmux bind "|" split-window -h
tmux bind - split-window -v
# Para matar la sesion
tmux bind z kill-session

# Titulo de paneles
tmux set -g pane-border-status top
tmux set -g pane-border-format "#{pane_index} #{pane_current_path}"
# No sacar los paneles cuando mueren para poder leer los logs cuando rompen
tmux set-option remain-on-exit on

sleep 0.5
tmux split-window -f -v -t tp:0 'sleep 0.5 && exec ./vexec cpu'
tmux select-pane -t 0
sleep 0.5
#tmux split-window -h -t tp 'exec ./vexec kernel'
tmux split-window -h -t tp 'sleep 0.5 && exec ./vexec consola ./consola/insts.txt 50'
tmux select-pane -t 2
#sleep 0.5
#tmux split-window -h -t tp 'exec ./vexec consola ./consola/insts.txt 50'
tmux split-window -h -t tp 'exec ./vexec kernel'

# Entrar a la sesion
tmux attach-session -t tp
