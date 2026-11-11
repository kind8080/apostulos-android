FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip nmap nuclei nikto sqlmap whatweb wapiti tshark ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/apostulos-agent
COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt
COPY agent.py .
RUN useradd --system --create-home --uid 10001 apostulos
USER apostulos
EXPOSE 8765
CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "8765"]
