FROM python:3.11-slim

WORKDIR /opt/template-filter
COPY template_filter.py filtercore.py ./

ENV TEMPLATE_FILTER_CONFIG=/data/config.json
EXPOSE 8336

CMD ["python3", "/opt/template-filter/template_filter.py"]
