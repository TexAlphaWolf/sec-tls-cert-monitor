FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . && useradd --system --no-create-home --uid 10001 tlswatch

# Root is not needed and the filesystem can be read-only. The exporter listens on 9117; inside a
# container it must bind to all interfaces: `serve --listen 0.0.0.0:9117 -c /config/hosts.toml`.
USER tlswatch
EXPOSE 9117
ENTRYPOINT ["tlswatch"]
CMD ["--help"]
