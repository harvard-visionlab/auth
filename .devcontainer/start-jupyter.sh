#!/bin/bash
# Start JupyterLab in the background

# Activate the virtual environment
source /work/auth/.venv/bin/activate

# Create jupyter config directory if it doesn't exist
mkdir -p ~/.jupyter

# Start JupyterLab with proper authentication disabled
jupyter lab \
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
    --ContentsManager.allow_hidden=True \
    2>&1 | tee /tmp/jupyter.log &

echo "JupyterLab is starting on port 8888..."
echo "Logs are available at /tmp/jupyter.log"
echo "Access JupyterLab at http://localhost:8888"
echo "No authentication token required"