FROM python:3.12-slim
RUN curl -fsSL -o /tmp/tool.tgz https://example.invalid/tool.tgz \
    && tar -xzf /tmp/tool.tgz -C /usr/local/bin
ADD https://example.invalid/data.json /srv/data.json
RUN pip install --no-cache-dir -r requirements.txt
