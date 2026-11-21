FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="mcp-guardrail-gateway" \
      org.opencontainers.image.description="Human-approved, verified, auto-rollback write actions for AI agents on Cisco MCP servers" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/natrajexplore/mcp_guardrails"
RUN useradd --create-home --uid 10001 guardrail && mkdir -p /data /config && chown guardrail /data
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
# Upstream MCP servers launched over stdio must be installed in this image, e.g.:
#   RUN pip install --no-cache-dir trustsec-policy-agent
USER guardrail
WORKDIR /data
ENV GUARDRAIL_CONFIG=/config/gateway.yaml PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"
ENTRYPOINT ["guardrail"]
CMD ["serve", "--transport", "http"]
