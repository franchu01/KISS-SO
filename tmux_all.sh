#!/bin/sh
cd "$(dirname "$0")"

# Matar la sesion vieja
tmux kill-session -t tp

# Crear sesion
tmux new-session -d -s tp './memoria/vexec'

# Para cambiar Ctrl B por Ctrl A
#set-option -g prefix C-A
# Mouse
tmux setw -g mouse on
# Para matar la sesion
tmux bind z kill-session

# Empezar la numeración de las ventanas creadas en 1 (la primera ventana)
tmux set -g base-index 1
# Titulo de paneles
tmux set -g pane-border-status top
tmux set -g pane-border-format "#{pane_index} #{pane_current_path}"
# No sacar los paneles cuando mueren para poder leer los logs cuando rompen
tmux set-option remain-on-exit on

sleep 0.5
tmux split-window -f -v -t tp:1 -c cpu 'exec ./vexec'
tmux select-pane -t 1
sleep 0.5
tmux split-window -h -t tp -c kernel 'exec ./vexec'
tmux select-pane -t 0
sleep 0.5
tmux split-window -h -t tp -c consola 'exec ./vexec ./test_file.txt 50'

# Entrar a la sesion
tmux attach-session -t tp
