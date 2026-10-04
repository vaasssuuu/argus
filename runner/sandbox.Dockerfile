# Sandbox image for executing PoCs. Deliberately minimal: stdlib only, no installed packages,
# no network tools. The isolation is NOT in this image — it comes from running the container on
# an internal Docker network (see egress.py). The image just carries the executor.
FROM python:3.11-slim
WORKDIR /app
COPY runner/execute.py ./execute.py
