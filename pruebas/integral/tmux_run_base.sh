#!/bin/sh
cd "$(dirname "$0")"

# Matar la sesion vieja
tmux kill-session -t tp

# Crear sesion
tmux new-session -d -s tp './vexec memoria'

# Mouse
tmux setw -g mouse on
tmux unbind -T copy-mode MouseDragEnd1Pane
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

sleep 1.5
tmux split-window -h -t tp 'exec ./vexec cpu'
tmux split-window -h -t tp 'sleep 3.0 && exec ./vexec kernel'
tmux split-window -h -t tp 'sleep 4.5 && exec ./vexec consola ./INTEGRAL_1 2048'
tmux split-window -h -t tp 'sleep 6.0 && exec ./vexec consola ./INTEGRAL_2 2048'
tmux split-window -h -t tp 'sleep 7.5 && exec ./vexec consola ./INTEGRAL_3 2048'
tmux split-window -h -t tp 'sleep 9.0 && exec ./vexec consola ./INTEGRAL_4 2048'
tmux split-window -h -t tp 'sleep 10.5 && exec ./vexec consola ./INTEGRAL_5 2048'


# Entrar a la sesion
tmux attach-session -t tp
