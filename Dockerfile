FROM python:3.11.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml /app/
COPY README.md /app/
COPY sandbox_escape_finder /app/sandbox_escape_finder
RUN pip install --no-cache-dir .
USER 65534:65534
ENTRYPOINT ["python", "-m", "sandbox_escape_finder.worker"]
