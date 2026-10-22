FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    suricata=1:7.0.3-1build3 libmodsecurity3t64=3.0.12-1.1build2 \
    libmodsecurity-dev=3.0.12-1.1build2 modsecurity-crs=3.3.5-2 \
    python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/validation
COPY requirements-validation.txt /tmp/requirements-validation.txt
RUN /opt/validation/bin/pip install --no-cache-dir -r /tmp/requirements-validation.txt
ENV PATH="/opt/validation/bin:${PATH}"
WORKDIR /work
USER 65532:65532
ENTRYPOINT ["python", "-B", "-m", "tools.validate_native"]
