# Target runtime container. Tiny app, two runtime deps — pip-installing the pinned
# versions directly is the fewest moving parts (uv manages the dev/project env; the
# target container only needs flask + pyyaml at runtime).
FROM python:3.11-slim

WORKDIR /app
COPY target/ ./target/
RUN pip install --no-cache-dir flask==3.1.3 pyyaml==6.0.3

ENV HOST=0.0.0.0 PORT=5000
EXPOSE 5000
CMD ["python", "-m", "target.app"]
