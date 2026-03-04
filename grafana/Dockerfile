FROM grafana/grafana:10.2.2

# Copy provisioning configs
COPY provisioning/datasources/datasource.yml /etc/grafana/provisioning/datasources/
COPY provisioning/dashboards/dashboard.yml /etc/grafana/provisioning/dashboards/

# Copy dashboards
COPY dashboards/ /var/lib/grafana/dashboards/
