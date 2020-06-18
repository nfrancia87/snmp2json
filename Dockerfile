FROM python:3.7-alpine
WORKDIR /app
RUN apk add --no-cache gcc musl-dev linux-headers net-snmp-tools libevent-dev openssl libffi-dev openssl-dev libressl-dev
COPY required_mibs.sh required_mibs.sh
COPY requirements.txt requirements.txt
CMD ["sudo chmod", "+x", "required_mibs.sh"]
CMD ["./","required_mibs.sh"]
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python3", "prod_api_snmp2json.py"]

