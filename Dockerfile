FROM python:3.12-slim@sha256:c3d81d25b3154142b0b42eb1e61300024426268edeb5b5a26dd7ddf64d9daf28

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends yara \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY rules ./rules
# Apache-2.0 4(a)/4(d): the image is a distributed copy of the Work, so it
# carries the License and the NOTICE attribution.
COPY LICENSE NOTICE ./

# Run as an unprivileged fixed UID. Samples are untrusted input parsed in-process
# by archive/format libraries, so a parser exploit must not land on root. The id
# is fixed rather than auto-assigned because the pilot bind-mounts a host storage
# directory, and install.sh chowns that directory to this same id.
RUN groupadd --system --gid 10001 masp \
    && useradd --system --uid 10001 --gid 10001 --home-dir /app --no-create-home masp \
    && mkdir -p /app/data /app/storage/samples /app/rules \
    && chown -R masp:masp /app

USER masp

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
