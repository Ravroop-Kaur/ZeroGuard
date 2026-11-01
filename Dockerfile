# Single container for Render: React build + FastAPI + OPA sidecar (private on 127.0.0.1).
ARG OPA_TAG=latest-static
FROM node:20-slim AS web
WORKDIR /web/frontend
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend .
RUN npm run build

FROM openpolicyagent/opa:${OPA_TAG} AS opa

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
COPY --from=opa /opa /usr/local/bin/opa
WORKDIR /srv
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app app
COPY --from=web /web/backend/static static
COPY policies/authorization.rego policies/data.json policies/
COPY policies/tests policy_tests
COPY backend/tests backend/tests
# Verification shows up in the Render build log; failures do not block the deploy.
RUN PYTHONPATH=/srv python -m pytest -q backend/tests || echo "!!! PYTEST FAILED (non-blocking)"
RUN opa test policies policy_tests || echo "!!! REGO TESTS FAILED (non-blocking)"
RUN rm -f /srv/zeroguard.db
COPY start.sh .
RUN useradd -m app && chown -R app /srv
USER app
CMD ["sh", "start.sh"]
