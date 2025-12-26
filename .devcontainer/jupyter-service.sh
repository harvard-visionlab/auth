#!/bin/bash
# Service script to ensure JupyterLab is running

# Check if jupyter is already running
if pgrep -f "jupyter-lab" > /dev/null; then
    echo "JupyterLab is already running"
else
    echo "Starting JupyterLab..."
    source /work/auth/.venv/bin/activate
    
    nohup jupyter lab \
        --ip=0.0.0.0 \
        --port=8888 \
        --no-browser \
        --allow-root \
        --IdentityProvider.token='' \
        --ServerApp.password='' \
        --ServerApp.token='' \
        --ServerApp.password_required=False \
        --ServerApp.root_dir=/work/auth \
        --ServerApp.allow_origin='*' \
        --ServerApp.disable_check_xsrf=True \
        > /tmp/jupyter.log 2>&1 &
    
    sleep 2
    if pgrep -f "jupyter-lab" > /dev/null; then
        echo "JupyterLab started successfully on port 8888"
        echo "Logs available at /tmp/jupyter.log"
    else
        echo "Failed to start JupyterLab. Check /tmp/jupyter.log for errors"
    fi
fi