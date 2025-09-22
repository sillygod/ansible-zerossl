# ZeroSSL Ansible Plugin Usage Examples

Comprehensive collection of real-world examples for using the ZeroSSL Ansible plugin in various scenarios.

## Table of Contents

- [Basic Examples](#basic-examples)
- [Web Server Integration](#web-server-integration)
- [Advanced Scenarios](#advanced-scenarios)
- [Production Playbooks](#production-playbooks)
- [Automation Workflows](#automation-workflows)
- [Troubleshooting Examples](#troubleshooting-examples)

## Basic Examples

### Single Domain Certificate

```yaml
---
- name: Basic SSL certificate for single domain
  hosts: webserver
  vars:
    domain_name: example.com
  tasks:
    - name: Create SSL certificate
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains:
          - "{{ domain_name }}"
        state: present
        certificate_path: "/etc/ssl/certs/{{ domain_name }}.crt"
        private_key_path: "/etc/ssl/private/{{ domain_name }}.key"
        validation_method: HTTP_CSR_HASH
        web_root: /var/www/html
      register: ssl_result

    - name: Display certificate information
      debug:
        msg: |
          Certificate created for {{ domain_name }}
          Certificate ID: {{ ssl_result.certificate_id }}
          Expires: {{ ssl_result.expires }}
          Status: {{ ssl_result.status }}
```

### Multi-Domain (SAN) Certificate

```yaml
---
- name: Multi-domain SSL certificate
  hosts: webserver
  vars:
    primary_domain: example.com
    additional_domains:
      - www.example.com
      - api.example.com
      - blog.example.com
  tasks:
    - name: Create multi-domain certificate
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ [primary_domain] + additional_domains }}"
        state: present
        certificate_path: "/etc/ssl/certs/{{ primary_domain }}.crt"
        private_key_path: "/etc/ssl/private/{{ primary_domain }}.key"
        ca_bundle_path: "/etc/ssl/certs/{{ primary_domain }}-ca.crt"
        full_chain_path: "/etc/ssl/certs/{{ primary_domain }}-fullchain.crt"
        validation_method: HTTP_CSR_HASH
        web_root: /var/www/html
        validity_days: 90
      register: multi_cert_result

    - name: Show all domains in certificate
      debug:
        msg: "Certificate covers domains: {{ multi_cert_result.domains | join(', ') }}"
```

### Wildcard Certificate with DNS Validation

```yaml
---
- name: Wildcard SSL certificate with DNS validation
  hosts: localhost
  vars:
    wildcard_domain: "*.example.com"
  tasks:
    - name: Request wildcard certificate
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains:
          - "{{ wildcard_domain }}"
        state: request
        validation_method: DNS_CSR_HASH
      register: wildcard_request

    - name: Display DNS validation requirements
      debug:
        msg: |
          To validate the wildcard certificate, add these DNS CNAME records:
          {% for record in wildcard_request.dns_records %}
          Name: {{ record.cname_validation_p1 }}
          Points To: {{ record.cname_validation_p2 }}
          ---
          {% endfor %}

    - name: Pause for manual DNS configuration
      pause:
        prompt: |
          Please add the DNS CNAME records shown above to your DNS provider.
          Press ENTER when the records are in place and have propagated.

    - name: Validate wildcard certificate
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        certificate_id: "{{ wildcard_request.certificate_id }}"
        state: validate
        validation_method: DNS_CSR_HASH

    - name: Download wildcard certificate
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        certificate_id: "{{ wildcard_request.certificate_id }}"
        state: download
        certificate_path: "/etc/ssl/certs/wildcard.example.com.crt"
        private_key_path: "/etc/ssl/private/wildcard.example.com.key"
        full_chain_path: "/etc/ssl/certs/wildcard.example.com-fullchain.crt"
```

## Web Server Integration

### Apache HTTPD Configuration

```yaml
---
- name: SSL certificate for Apache HTTPD
  hosts: apache_servers
  vars:
    site_domain: mysite.example.com
    apache_ssl_dir: /etc/httpd/ssl
  tasks:
    - name: Create SSL directory
      file:
        path: "{{ apache_ssl_dir }}"
        state: directory
        mode: '0755'
        owner: root
        group: root

    - name: Generate SSL certificate
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains:
          - "{{ site_domain }}"
        state: present
        certificate_path: "{{ apache_ssl_dir }}/{{ site_domain }}.crt"
        private_key_path: "{{ apache_ssl_dir }}/{{ site_domain }}.key"
        ca_bundle_path: "{{ apache_ssl_dir }}/{{ site_domain }}-ca.crt"
        full_chain_path: "{{ apache_ssl_dir }}/{{ site_domain }}-fullchain.crt"
        validation_method: HTTP_CSR_HASH
        web_root: /var/www/html
        file_mode: '0644'
        private_key_mode: '0600'
      notify: restart apache
      register: ssl_cert

    - name: Configure Apache SSL virtual host
      template:
        src: ssl-vhost.conf.j2
        dest: "/etc/httpd/conf.d/{{ site_domain }}-ssl.conf"
        backup: yes
      notify: restart apache
      vars:
        server_name: "{{ site_domain }}"
        cert_file: "{{ apache_ssl_dir }}/{{ site_domain }}-fullchain.crt"
        key_file: "{{ apache_ssl_dir }}/{{ site_domain }}.key"

  handlers:
    - name: restart apache
      service:
        name: httpd
        state: restarted
```

### Nginx Configuration

```yaml
---
- name: SSL certificate for Nginx
  hosts: nginx_servers
  vars:
    app_domains:
      - app.example.com
      - www.app.example.com
    nginx_ssl_dir: /etc/nginx/ssl
  tasks:
    - name: Create Nginx SSL directory
      file:
        path: "{{ nginx_ssl_dir }}"
        state: directory
        mode: '0755'
        owner: root
        group: root

    - name: Generate SSL certificate for application
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ app_domains }}"
        state: present
        certificate_path: "{{ nginx_ssl_dir }}/app.example.com.crt"
        private_key_path: "{{ nginx_ssl_dir }}/app.example.com.key"
        full_chain_path: "{{ nginx_ssl_dir }}/app.example.com-fullchain.crt"
        validation_method: HTTP_CSR_HASH
        web_root: /var/www/html
        renew_threshold_days: 14
      notify:
        - reload nginx
      register: app_ssl_cert

    - name: Configure Nginx SSL server block
      template:
        src: nginx-ssl.conf.j2
        dest: "/etc/nginx/sites-available/{{ app_domains[0] }}-ssl"
        backup: yes
      notify:
        - reload nginx
      vars:
        server_names: "{{ app_domains | join(' ') }}"
        cert_file: "{{ nginx_ssl_dir }}/app.example.com-fullchain.crt"
        key_file: "{{ nginx_ssl_dir }}/app.example.com.key"

    - name: Enable SSL site
      file:
        src: "/etc/nginx/sites-available/{{ app_domains[0] }}-ssl"
        dest: "/etc/nginx/sites-enabled/{{ app_domains[0] }}-ssl"
        state: link
      notify:
        - reload nginx

    - name: Test Nginx configuration
      command: nginx -t
      changed_when: false

  handlers:
    - name: reload nginx
      service:
        name: nginx
        state: reloaded
```

### HAProxy Configuration

```yaml
---
- name: SSL certificate for HAProxy
  hosts: loadbalancers
  vars:
    lb_domains:
      - lb.example.com
      - api.example.com
    haproxy_ssl_dir: /etc/haproxy/ssl
  tasks:
    - name: Create HAProxy SSL directory
      file:
        path: "{{ haproxy_ssl_dir }}"
        state: directory
        mode: '0750'
        owner: haproxy
        group: haproxy

    - name: Generate SSL certificate for load balancer
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ lb_domains }}"
        state: present
        certificate_path: "/tmp/lb.example.com.crt"
        private_key_path: "/tmp/lb.example.com.key"
        ca_bundle_path: "/tmp/lb.example.com-ca.crt"
        validation_method: HTTP_CSR_HASH
        web_root: /var/www/html
      register: lb_ssl_cert

    - name: Combine certificate and key for HAProxy
      shell: |
        cat /tmp/lb.example.com.crt \
            /tmp/lb.example.com-ca.crt \
            /tmp/lb.example.com.key > {{ haproxy_ssl_dir }}/lb.example.com.pem
      when: lb_ssl_cert.changed

    - name: Set proper permissions for HAProxy certificate bundle
      file:
        path: "{{ haproxy_ssl_dir }}/lb.example.com.pem"
        mode: '0640'
        owner: haproxy
        group: haproxy

    - name: Clean up temporary certificate files
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /tmp/lb.example.com.crt
        - /tmp/lb.example.com.key
        - /tmp/lb.example.com-ca.crt

    - name: Update HAProxy configuration
      template:
        src: haproxy.cfg.j2
        dest: /etc/haproxy/haproxy.cfg
        backup: yes
      notify: reload haproxy
      vars:
        ssl_cert_file: "{{ haproxy_ssl_dir }}/lb.example.com.pem"

  handlers:
    - name: reload haproxy
      service:
        name: haproxy
        state: reloaded
```

## Advanced Scenarios

### Certificate Renewal Automation

```yaml
---
- name: Automated certificate renewal
  hosts: all
  vars:
    certificates:
      - domains: [example.com, www.example.com]
        cert_path: /etc/ssl/certs/example.com.crt
        key_path: /etc/ssl/private/example.com.key
        service: nginx
      - domains: [api.example.com]
        cert_path: /etc/ssl/certs/api.example.com.crt
        key_path: /etc/ssl/private/api.example.com.key
        service: apache2
      - domains: ["*.internal.example.com"]
        cert_path: /etc/ssl/certs/wildcard.internal.crt
        key_path: /etc/ssl/private/wildcard.internal.key
        validation_method: DNS_CSR_HASH
        service: haproxy

  tasks:
    - name: Check certificate renewal status
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ item.domains }}"
        state: check_renew_or_create
        renew_threshold_days: 30
      register: renewal_checks
      loop: "{{ certificates }}"

    - name: Renew certificates that need renewal
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ item.item.domains }}"
        state: present
        certificate_path: "{{ item.item.cert_path }}"
        private_key_path: "{{ item.item.key_path }}"
        validation_method: "{{ item.item.validation_method | default('HTTP_CSR_HASH') }}"
        web_root: "{{ item.item.web_root | default('/var/www/html') }}"
        force: true
      when: item.needs_renewal
      loop: "{{ renewal_checks.results }}"
      notify:
        - restart services
      register: renewed_certs

    - name: Send renewal notification
      mail:
        to: "{{ admin_email }}"
        subject: "SSL Certificate Renewal Report"
        body: |
          SSL Certificate Renewal Report

          Certificates checked: {{ certificates | length }}
          Certificates renewed: {{ renewed_certs.results | selectattr('changed') | list | length }}

          Renewed certificates:
          {% for result in renewed_certs.results %}
          {% if result.changed %}
          - {{ result.domains | join(', ') }} (expires: {{ result.expires }})
          {% endif %}
          {% endfor %}
      when: renewed_certs.results | selectattr('changed') | list | length > 0

  handlers:
    - name: restart services
      service:
        name: "{{ item.item.service }}"
        state: restarted
      loop: "{{ renewed_certs.results }}"
      when: item.changed
```

### Split Workflow with Custom CSR

```yaml
---
- name: Advanced certificate workflow with custom CSR
  hosts: localhost
  vars:
    company_domains:
      - corporate.example.com
      - intranet.example.com
    cert_subject: "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=corporate.example.com"
  tasks:
    - name: Generate custom private key
      openssl_privatekey:
        path: /tmp/corporate.key
        size: 4096
        type: RSA

    - name: Generate certificate signing request
      openssl_csr:
        path: /tmp/corporate.csr
        privatekey_path: /tmp/corporate.key
        subject: "{{ cert_subject }}"
        subject_alt_name: "{{ company_domains | map('regex_replace', '^', 'DNS:') | list }}"
        digest: sha256

    - name: Request certificate with custom CSR
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ company_domains }}"
        state: request
        csr_path: /tmp/corporate.csr
        validation_method: HTTP_CSR_HASH
      register: corp_cert_request

    - name: Create validation directory structure
      file:
        path: "/var/www/{{ item.domain }}/.well-known/pki-validation"
        state: directory
        mode: '0755'
      loop: "{{ corp_cert_request.validation_files }}"

    - name: Place validation files
      copy:
        content: "{{ item.content }}"
        dest: "/var/www/{{ item.domain }}/{{ item.url_path }}"
        mode: '0644'
      loop: "{{ corp_cert_request.validation_files }}"

    - name: Wait for validation files to be accessible
      uri:
        url: "http://{{ item.domain }}{{ item.url_path }}"
        method: GET
        return_content: yes
      register: validation_check
      until: validation_check.content == item.content
      retries: 5
      delay: 10
      loop: "{{ corp_cert_request.validation_files }}"

    - name: Validate certificate
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        certificate_id: "{{ corp_cert_request.certificate_id }}"
        state: validate
        validation_method: HTTP_CSR_HASH

    - name: Poll for certificate issuance
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        certificate_id: "{{ corp_cert_request.certificate_id }}"
        state: download
        certificate_path: /etc/ssl/certs/corporate.crt
        ca_bundle_path: /etc/ssl/certs/corporate-ca.crt
        full_chain_path: /etc/ssl/certs/corporate-fullchain.crt
      register: download_result
      until: download_result is succeeded
      retries: 10
      delay: 30

    - name: Copy private key to final location
      copy:
        src: /tmp/corporate.key
        dest: /etc/ssl/private/corporate.key
        mode: '0600'
        owner: root
        group: root
        remote_src: yes

    - name: Clean up temporary files
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /tmp/corporate.key
        - /tmp/corporate.csr
```

### Environment-Specific Configuration

```yaml
---
- name: Environment-specific SSL certificates
  hosts: "{{ target_env }}"
  vars:
    ssl_configs:
      development:
        domains: [dev.example.com, dev-api.example.com]
        validity_days: 90
        renew_threshold: 45
        validation_method: HTTP_CSR_HASH
      staging:
        domains: [staging.example.com, staging-api.example.com]
        validity_days: 90
        renew_threshold: 30
        validation_method: HTTP_CSR_HASH
      production:
        domains: [example.com, www.example.com, api.example.com]
        validity_days: 365
        renew_threshold: 30
        validation_method: DNS_CSR_HASH

  tasks:
    - name: Set environment-specific variables
      set_fact:
        env_config: "{{ ssl_configs[target_env] }}"

    - name: Create SSL certificate for environment
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ env_config.domains }}"
        state: present
        certificate_path: "/etc/ssl/certs/{{ target_env }}.crt"
        private_key_path: "/etc/ssl/private/{{ target_env }}.key"
        full_chain_path: "/etc/ssl/certs/{{ target_env }}-fullchain.crt"
        validation_method: "{{ env_config.validation_method }}"
        validity_days: "{{ env_config.validity_days }}"
        renew_threshold_days: "{{ env_config.renew_threshold }}"
        web_root: "/var/www/{{ target_env }}"
      register: env_ssl_result

    - name: Configure environment-specific web server
      template:
        src: "{{ target_env }}-nginx.conf.j2"
        dest: "/etc/nginx/sites-available/{{ target_env }}"
      notify: reload nginx
      vars:
        ssl_certificate: "/etc/ssl/certs/{{ target_env }}-fullchain.crt"
        ssl_certificate_key: "/etc/ssl/private/{{ target_env }}.key"

  handlers:
    - name: reload nginx
      service:
        name: nginx
        state: reloaded
```

## Production Playbooks

### Complete LAMP Stack with SSL

```yaml
---
- name: Deploy LAMP stack with SSL certificates
  hosts: web_servers
  become: yes
  vars:
    app_name: myapp
    app_domains:
      - myapp.example.com
      - www.myapp.example.com
    database_name: myapp_db

  tasks:
    - name: Install LAMP stack packages
      package:
        name:
          - apache2
          - mysql-server
          - php
          - php-mysql
          - python3-pymysql
        state: present

    - name: Start and enable services
      service:
        name: "{{ item }}"
        state: started
        enabled: yes
      loop:
        - apache2
        - mysql

    - name: Enable Apache SSL module
      apache2_module:
        name: ssl
        state: present
      notify: restart apache

    - name: Create application database
      mysql_db:
        name: "{{ database_name }}"
        state: present

    - name: Create SSL directory
      file:
        path: /etc/apache2/ssl
        state: directory
        mode: '0755'

    - name: Generate SSL certificate
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ app_domains }}"
        state: present
        certificate_path: "/etc/apache2/ssl/{{ app_name }}.crt"
        private_key_path: "/etc/apache2/ssl/{{ app_name }}.key"
        ca_bundle_path: "/etc/apache2/ssl/{{ app_name }}-ca.crt"
        full_chain_path: "/etc/apache2/ssl/{{ app_name }}-fullchain.crt"
        validation_method: HTTP_CSR_HASH
        web_root: /var/www/html
        renew_threshold_days: 30
      notify: restart apache
      register: ssl_cert

    - name: Deploy application files
      git:
        repo: "{{ app_repo_url }}"
        dest: "/var/www/{{ app_name }}"
        version: "{{ app_version | default('main') }}"
      notify: restart apache

    - name: Configure Apache virtual host
      template:
        src: lamp-vhost.conf.j2
        dest: "/etc/apache2/sites-available/{{ app_name }}.conf"
      notify: restart apache
      vars:
        server_name: "{{ app_domains[0] }}"
        server_aliases: "{{ app_domains[1:] | join(' ') }}"
        document_root: "/var/www/{{ app_name }}"
        ssl_certificate: "/etc/apache2/ssl/{{ app_name }}-fullchain.crt"
        ssl_certificate_key: "/etc/apache2/ssl/{{ app_name }}.key"

    - name: Enable application site
      command: a2ensite {{ app_name }}
      notify: restart apache

    - name: Disable default site
      command: a2dissite 000-default
      notify: restart apache

    - name: Set up certificate renewal cron job
      cron:
        name: "SSL certificate renewal for {{ app_name }}"
        minute: "0"
        hour: "2"
        day: "1"
        job: >
          /usr/bin/ansible-playbook /opt/ssl-renewal.yml
          --extra-vars "target_domains={{ app_domains | join(',') }}"

  handlers:
    - name: restart apache
      service:
        name: apache2
        state: restarted
```

### Microservices SSL Setup

```yaml
---
- name: SSL certificates for microservices architecture
  hosts: kubernetes_cluster
  vars:
    microservices:
      - name: user-service
        domains: [users.api.example.com]
        namespace: production
      - name: order-service
        domains: [orders.api.example.com]
        namespace: production
      - name: payment-service
        domains: [payments.api.example.com]
        namespace: production
      - name: notification-service
        domains: [notifications.api.example.com]
        namespace: production

  tasks:
    - name: Create namespace for SSL certificates
      kubernetes.core.k8s:
        name: ssl-certificates
        api_version: v1
        kind: Namespace
        state: present

    - name: Generate SSL certificates for microservices
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ item.domains }}"
        state: present
        certificate_path: "/tmp/{{ item.name }}.crt"
        private_key_path: "/tmp/{{ item.name }}.key"
        full_chain_path: "/tmp/{{ item.name }}-fullchain.crt"
        validation_method: DNS_CSR_HASH
      register: microservice_certs
      loop: "{{ microservices }}"

    - name: Create Kubernetes TLS secrets
      kubernetes.core.k8s:
        definition:
          apiVersion: v1
          kind: Secret
          metadata:
            name: "{{ item.item.name }}-tls"
            namespace: "{{ item.item.namespace }}"
          type: kubernetes.io/tls
          data:
            tls.crt: "{{ lookup('file', '/tmp/' + item.item.name + '-fullchain.crt') | b64encode }}"
            tls.key: "{{ lookup('file', '/tmp/' + item.item.name + '.key') | b64encode }}"
      loop: "{{ microservice_certs.results }}"
      when: item.changed

    - name: Create ingress with SSL termination
      kubernetes.core.k8s:
        definition:
          apiVersion: networking.k8s.io/v1
          kind: Ingress
          metadata:
            name: microservices-ingress
            namespace: production
            annotations:
              nginx.ingress.kubernetes.io/ssl-redirect: "true"
              nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
          spec:
            tls:
              - hosts: "{{ item.domains }}"
                secretName: "{{ item.name }}-tls"
            rules:
              - host: "{{ item.domains[0] }}"
                http:
                  paths:
                    - path: /
                      pathType: Prefix
                      backend:
                        service:
                          name: "{{ item.name }}"
                          port:
                            number: 80
      loop: "{{ microservices }}"

    - name: Clean up temporary certificate files
      file:
        path: "/tmp/{{ item.name }}{{ suffix }}"
        state: absent
      loop: "{{ microservices }}"
      with_items:
        - .crt
        - .key
        - -fullchain.crt
      loop_control:
        extended: yes
        loop_var: suffix
```

## Automation Workflows

### CI/CD Pipeline Integration

```yaml
---
- name: SSL certificate automation for CI/CD
  hosts: localhost
  connection: local
  vars:
    environments:
      - name: development
        domains: [dev-app.example.com]
        branch: develop
      - name: staging
        domains: [staging-app.example.com]
        branch: staging
      - name: production
        domains: [app.example.com, www.app.example.com]
        branch: main

  tasks:
    - name: Check if deployment should proceed
      uri:
        url: "{{ ci_api_url }}/build/status"
        headers:
          Authorization: "Bearer {{ ci_api_token }}"
      register: build_status

    - name: Generate SSL certificates for environments
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ item.domains }}"
        state: present
        certificate_path: "/opt/certs/{{ item.name }}.crt"
        private_key_path: "/opt/certs/{{ item.name }}.key"
        full_chain_path: "/opt/certs/{{ item.name }}-fullchain.crt"
        validation_method: HTTP_CSR_HASH
        web_root: "/var/www/{{ item.name }}"
      loop: "{{ environments }}"
      when: build_status.json.status == "success"
      register: env_certificates

    - name: Upload certificates to deployment artifact storage
      aws_s3:
        bucket: "{{ deployment_bucket }}"
        object: "certificates/{{ item.item.name }}/{{ ansible_date_time.epoch }}/{{ cert_file }}"
        src: "/opt/certs/{{ item.item.name }}{{ cert_file }}"
        mode: put
        encrypt: yes
      loop: "{{ env_certificates.results }}"
      with_items:
        - .crt
        - .key
        - -fullchain.crt
      loop_control:
        extended: yes
        loop_var: cert_file
      when: item.changed

    - name: Trigger deployment pipeline
      uri:
        url: "{{ ci_api_url }}/deploy"
        method: POST
        headers:
          Authorization: "Bearer {{ ci_api_token }}"
        body_format: json
        body:
          environment: "{{ item.name }}"
          ssl_certificates_updated: "{{ item.changed | bool }}"
      loop: "{{ env_certificates.results }}"
      when: env_certificates is defined
```

### Automated Certificate Monitoring

```yaml
---
- name: SSL certificate monitoring and alerting
  hosts: monitoring_server
  vars:
    monitored_certificates:
      - name: main-website
        domains: [example.com, www.example.com]
        critical_days: 7
        warning_days: 30
      - name: api-gateway
        domains: [api.example.com]
        critical_days: 14
        warning_days: 30
      - name: admin-panel
        domains: [admin.example.com]
        critical_days: 7
        warning_days: 21

  tasks:
    - name: Check certificate expiration status
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains: "{{ item.domains }}"
        state: check_renew_or_create
        renew_threshold_days: "{{ item.warning_days }}"
      register: cert_status_checks
      loop: "{{ monitored_certificates }}"

    - name: Create monitoring alerts for certificates
      set_fact:
        certificate_alerts: >
          {{
            certificate_alerts | default([]) +
            [{
              'name': item.item.name,
              'domains': item.item.domains,
              'days_until_expiry': item.days_until_expiry | default(-1),
              'expires': item.expires,
              'needs_renewal': item.needs_renewal,
              'alert_level': (
                'critical' if (item.days_until_expiry | default(999)) <= item.item.critical_days
                else 'warning' if item.needs_renewal
                else 'ok'
              )
            }]
          }}
      loop: "{{ cert_status_checks.results }}"

    - name: Send critical alerts
      mail:
        to: "{{ alert_email_critical }}"
        subject: "CRITICAL: SSL Certificate Expiring Soon"
        body: |
          The following SSL certificates require immediate attention:

          {% for alert in certificate_alerts %}
          {% if alert.alert_level == 'critical' %}
          Certificate: {{ alert.name }}
          Domains: {{ alert.domains | join(', ') }}
          Expires: {{ alert.expires }}
          Days remaining: {{ alert.days_until_expiry }}

          {% endif %}
          {% endfor %}
      when: certificate_alerts | selectattr('alert_level', 'equalto', 'critical') | list | length > 0

    - name: Send warning alerts
      mail:
        to: "{{ alert_email_warning }}"
        subject: "WARNING: SSL Certificate Renewal Required"
        body: |
          The following SSL certificates should be renewed soon:

          {% for alert in certificate_alerts %}
          {% if alert.alert_level == 'warning' %}
          Certificate: {{ alert.name }}
          Domains: {{ alert.domains | join(', ') }}
          Expires: {{ alert.expires }}
          Days remaining: {{ alert.days_until_expiry }}

          {% endif %}
          {% endfor %}
      when: certificate_alerts | selectattr('alert_level', 'equalto', 'warning') | list | length > 0

    - name: Update monitoring dashboard
      uri:
        url: "{{ monitoring_api_url }}/certificates"
        method: POST
        headers:
          Authorization: "Bearer {{ monitoring_api_token }}"
        body_format: json
        body:
          timestamp: "{{ ansible_date_time.epoch }}"
          certificates: "{{ certificate_alerts }}"
```

## Troubleshooting Examples

### Debug Mode and Validation Testing

```yaml
---
- name: SSL certificate troubleshooting and validation
  hosts: localhost
  vars:
    debug_domain: test.example.com

  tasks:
    - name: Test certificate creation with maximum verbosity
      zerossl_certificate:
        api_key: "{{ vault_zerossl_api_key }}"
        domains:
          - "{{ debug_domain }}"
        state: request
        validation_method: HTTP_CSR_HASH
      register: debug_cert_request
      failed_when: false

    - name: Display detailed request information
      debug:
        var: debug_cert_request
        verbosity: 2

    - name: Check validation file accessibility
      uri:
        url: "http://{{ debug_domain }}{{ item.url_path }}"
        method: GET
        return_content: yes
        status_code: [200, 404]
      register: validation_tests
      loop: "{{ debug_cert_request.validation_files | default([]) }}"
      failed_when: false

    - name: Report validation file test results
      debug:
        msg: |
          Validation file test for {{ item.item.domain }}:
          URL: http://{{ debug_domain }}{{ item.item.url_path }}
          Status: {{ item.status }}
          {% if item.status == 200 %}
          Content matches: {{ (item.content == item.item.content) | ternary('YES', 'NO') }}
          {% else %}
          Error: File not accessible
          {% endif %}
      loop: "{{ validation_tests.results }}"
      when: validation_tests.results is defined

    - name: Test DNS resolution for domain
      command: dig +short {{ debug_domain }}
      register: dns_check
      changed_when: false
      failed_when: false

    - name: Report DNS status
      debug:
        msg: |
          DNS Resolution for {{ debug_domain }}:
          {% if dns_check.stdout %}
          IP Addresses: {{ dns_check.stdout_lines | join(', ') }}
          {% else %}
          ERROR: Domain does not resolve
          {% endif %}

    - name: Test HTTP connectivity
      uri:
        url: "http://{{ debug_domain }}"
        method: HEAD
        follow_redirects: none
        status_code: [200, 301, 302, 404]
      register: http_test
      failed_when: false

    - name: Report HTTP connectivity
      debug:
        msg: |
          HTTP Connectivity to {{ debug_domain }}:
          Status: {{ http_test.status | default('FAILED') }}
          {% if http_test.status is defined %}
          Response time: {{ http_test.elapsed }}s
          {% endif %}
```

### Error Recovery and Retry Logic

```yaml
---
- name: SSL certificate with comprehensive error handling
  hosts: web_servers
  vars:
    max_retries: 3
    retry_delay: 300  # 5 minutes

  tasks:
    - name: Attempt certificate creation with retries
      block:
        - name: Create SSL certificate
          zerossl_certificate:
            api_key: "{{ vault_zerossl_api_key }}"
            domains:
              - "{{ ansible_fqdn }}"
            state: present
            certificate_path: "/etc/ssl/certs/{{ ansible_fqdn }}.crt"
            private_key_path: "/etc/ssl/private/{{ ansible_fqdn }}.key"
            validation_method: HTTP_CSR_HASH
            web_root: /var/www/html
            timeout: 60
          register: ssl_result

      rescue:
        - name: Handle rate limiting errors
          block:
            - debug:
                msg: "Rate limit exceeded, waiting {{ ssl_result.error.retry_after | default(retry_delay) }} seconds"

            - wait_for:
                timeout: "{{ ssl_result.error.retry_after | default(retry_delay) }}"

            - name: Retry after rate limit
              zerossl_certificate:
                api_key: "{{ vault_zerossl_api_key }}"
                domains:
                  - "{{ ansible_fqdn }}"
                state: present
                certificate_path: "/etc/ssl/certs/{{ ansible_fqdn }}.crt"
                private_key_path: "/etc/ssl/private/{{ ansible_fqdn }}.key"
                validation_method: HTTP_CSR_HASH
                web_root: /var/www/html
              register: ssl_result
          when: ssl_result.error.type == "ZeroSSLRateLimitError"

        - name: Handle validation errors
          block:
            - debug:
                msg: "Validation failed, checking web server configuration"

            - name: Ensure web server is running
              service:
                name: "{{ web_server_service }}"
                state: started

            - name: Ensure validation directory exists
              file:
                path: /var/www/html/.well-known/pki-validation
                state: directory
                mode: '0755'
                owner: www-data
                group: www-data

            - name: Test validation directory accessibility
              uri:
                url: "http://{{ ansible_fqdn }}/.well-known/pki-validation/"
                method: HEAD
                status_code: [200, 403, 404]

            - name: Retry certificate creation after fixes
              zerossl_certificate:
                api_key: "{{ vault_zerossl_api_key }}"
                domains:
                  - "{{ ansible_fqdn }}"
                state: present
                certificate_path: "/etc/ssl/certs/{{ ansible_fqdn }}.crt"
                private_key_path: "/etc/ssl/private/{{ ansible_fqdn }}.key"
                validation_method: HTTP_CSR_HASH
                web_root: /var/www/html
              register: ssl_result
          when: ssl_result.error.type == "ZeroSSLValidationError"

        - name: Handle file system errors
          block:
            - debug:
                msg: "File system error, checking permissions and disk space"

            - name: Check disk space
              shell: df -h /etc/ssl/
              register: disk_space

            - debug:
                var: disk_space.stdout_lines

            - name: Ensure SSL directories exist with proper permissions
              file:
                path: "{{ item }}"
                state: directory
                mode: '0755'
                owner: root
                group: root
              loop:
                - /etc/ssl/certs
                - /etc/ssl/private

            - name: Retry with corrected permissions
              zerossl_certificate:
                api_key: "{{ vault_zerossl_api_key }}"
                domains:
                  - "{{ ansible_fqdn }}"
                state: present
                certificate_path: "/etc/ssl/certs/{{ ansible_fqdn }}.crt"
                private_key_path: "/etc/ssl/private/{{ ansible_fqdn }}.key"
                validation_method: HTTP_CSR_HASH
                web_root: /var/www/html
              register: ssl_result
          when: ssl_result.error.type == "ZeroSSLFileSystemError"

        - name: Log unhandled errors
          debug:
            msg: |
              Unhandled error occurred:
              Type: {{ ssl_result.error.type | default('Unknown') }}
              Message: {{ ssl_result.error.message | default('No message') }}
              Retryable: {{ ssl_result.error.retryable | default(false) }}

        - name: Fail if error is not retryable
          fail:
            msg: "Certificate creation failed with non-retryable error: {{ ssl_result.error.message }}"
          when: not (ssl_result.error.retryable | default(false))

      always:
        - name: Log certificate operation result
          lineinfile:
            path: /var/log/ssl-certificates.log
            line: "{{ ansible_date_time.iso8601 }} - {{ ansible_fqdn }} - {{ ssl_result.msg | default('ERROR: ' + ssl_result.error.message | default('Unknown error')) }}"
            create: yes
```

These examples demonstrate the flexibility and power of the ZeroSSL Ansible plugin across various real-world scenarios, from simple single-domain certificates to complex enterprise deployments with monitoring, automation, and error handling.
