# python 3 headers, required for Ansible contributions
# https://csrgenerator.com/
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
  name: zerossl_certificate
  author: jing 
  version_added: "2.10"
  short_description: Manage SSL certificates using ZeroSSL API
  description:
    - Interact with ZeroSSL API to create, validate, and download SSL certificates.
    - Supports HTTP-01 validation (via file-based method).
    - You can split the flow into three steps using different 'state':
      - request (create cert, return challenge)
      - validate (validate a pending cert)
      - download (download issued cert)
  options:
    api_key:
      description: ZeroSSL API key
      required: true
      type: str
    csr_path:
      description: Path to CSR file (required for request or present)
      required: false
      type: str
    domains:
      description: List of domains to cover
      required: true
      type: list
      elements: str
    certificate_id:
      description: Certificate ID (required for validate/download)
      required: false
      type: str
    certificate_path:
      description: Path to save fullchain PEM
      required: false
      type: str
    validation_method:
      description: Method for domain validation
      default: HTTP_CSR_HASH
      choices: [HTTP_CSR_HASH]
      type: str
    state:
      description: Certificate state
      default: present
      choices: [present, request, validate, download, absent, check_renew_or_create]
      type: str
    renew_threshold_days:
      description: Days before expiration to trigger renewal
      default: 5
      type: int
'''

from ansible.plugins.action import ActionBase
from ansible.module_utils.common.text.converters import to_text
from ansible.errors import AnsibleActionFail

import json
import os
import zipfile
import io
from datetime import datetime, timedelta


class ZeroSSLException(Exception):
    """Custom exception for ZeroSSL operations"""
    retryable = True
    error_type = "general"

    def __init__(self, message):
        super().__init__(message)


class ZeroSSLValidationError(ZeroSSLException):
    """Exception for validation errors (now retryable)"""
    retryable = True
    error_type = "validation"


class ZeroSSLHTTPError(ZeroSSLException):
    """Exception for HTTP/API errors (retryable)"""
    retryable = True
    error_type = "http"


class ZeroSSLFileError(ZeroSSLException):
    """Exception for file operations (retryable)"""
    retryable = True
    error_type = "file"


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)
        module_args = self._task.args.copy()

        api_key = module_args.get('api_key')
        csr_path = module_args.get('csr_path')
        domains = module_args.get('domains')
        certificate_path = module_args.get('certificate_path')
        certificate_id = module_args.get('certificate_id')
        validation_method = module_args.get('validation_method', 'HTTP_CSR_HASH')
        state = module_args.get('state', 'present')
        renew_threshold_days = module_args.get('renew_threshold_days', 5)
        csr_content = None

        result['changed'] = False
        result['certificate_id'] = None
        result['validation_files'] = None

        if not api_key or not domains:
            raise AnsibleActionFail("api_key and domains are required")

        try:
            return self._execute_operation(result, api_key, csr_path, domains, certificate_path,
                                         certificate_id, validation_method, state,
                                         renew_threshold_days, csr_content, task_vars)
        except ZeroSSLException as e:
            if not e.retryable:
                raise AnsibleActionFail(str(e))

            result['failed'] = True
            result['msg'] = str(e)
            result['error_type'] = e.error_type
            return result

    def _execute_operation(self, result, api_key, csr_path, domains, certificate_path,
                          certificate_id, validation_method, state, renew_threshold_days,
                          csr_content, task_vars):

        if state in ['present', 'request']:
            if not csr_path:
                raise AnsibleActionFail("csr_path is required for state=present or request")

            try:
                with open(csr_path, 'r') as f:
                    csr_content = f.read()
            except Exception as e:
                raise ZeroSSLFileError(f"Failed to read CSR from {csr_path}: {str(e)}")

        if state == 'request' and csr_content:
            response = self._create_certificate(api_key, csr_content, domains, validation_method, task_vars)
            result['changed'] = True
            result['certificate_id'] = response['id']
            result['validation_files'] = self._build_validation_files(response['validation']['other_methods'], domains)
            return result

        elif state == 'validate':
            if not certificate_id:
                certificate_id = self._get_certificate_id(api_key, domains, task_vars)

            validate_result = self._validate_certificate(api_key, certificate_id, validation_method, task_vars)
            result['changed'] = True
            result['validation_result'] = validate_result
            return result

        elif state == 'download':
            if not certificate_id:
                certificate_id = self._get_certificate_id(api_key, domains, task_vars, status='issued')
            if not certificate_id:
                raise ZeroSSLHTTPError("certificate_id not found")
            content = self._download_certificate(api_key, certificate_id, task_vars)
            if not certificate_path:
                raise AnsibleActionFail("certificate_path is required for download")
            self._save_certificate(content, certificate_path)
            result['changed'] = True
            return result

        elif state == 'check_renew_or_create':
            certificate_id = self._get_certificate_id(api_key, domains, task_vars, status='issued')

            if not certificate_id:
                # means we need to create the certs
                result['needs_renewal'] = True
                result['changed'] = False
                return result

            needs_renewal = False
            if certificate_id:
                info = self._get_certificate_info(api_key, certificate_id, task_vars)
                expires_at = datetime.strptime(info.get('expires'), '%Y-%m-%d %H:%M:%S')
                renew_at = datetime.utcnow() + timedelta(days=int(renew_threshold_days))

                if expires_at > renew_at:
                    result['msg'] = f"Certificate still valid until {expires_at}"
                    result['needs_renewal'] = False
                    result['changed'] = False
                else:
                    needs_renewal = True
                    result['needs_renewal'] = True
                    result['expires_at'] = expires_at.strftime('%Y-%m-%d %H:%M:%S')
                    result['changed'] = True

            return result

        elif state == 'present':
            certificate_id = self._get_certificate_id(api_key, domains, task_vars)
            needs_renewal = False
            if certificate_id:
                info = self._get_certificate_info(api_key, certificate_id, task_vars)
                expires_at = datetime.strptime(info.get('expires'), '%Y-%m-%d %H:%M:%S')
                renew_at = datetime.utcnow() + timedelta(days=renew_threshold_days)
                if expires_at > renew_at:
                    result['msg'] = f"Certificate still valid until {expires_at}"
                    return result
                else:
                    needs_renewal = True

            if not certificate_id or needs_renewal:
                response = self._create_certificate(api_key, csr_content, domains, validation_method, task_vars)
                result['certificate_id'] = response['id']
                result['changed'] = True
                # continue inline to validate & download
                self._validate_certificate(api_key, response['id'], validation_method, task_vars)
                content = self._download_certificate(api_key, response['id'], task_vars)
                if not certificate_path:
                    raise AnsibleActionFail("certificate_path is required to save certificate")
                self._save_certificate(content, certificate_path)
                result['changed'] = True
            return result

        elif state == 'absent':
            certificate_id = self._get_certificate_id(api_key, domains, task_vars)
            if certificate_id:
                cancel_result = self._cancel_certificate(api_key, certificate_id, task_vars)
                result['changed'] = cancel_result.get('success', False)
            return result

        else:
            raise AnsibleActionFail(f"Unsupported state: {state}")

    def _execute_module_safe(self, module_name, module_args, task_vars):
        """Safely execute a module with proper error handling for delegation"""
        try:
            # Create a copy of task_vars to avoid modifying the original
            safe_task_vars = task_vars.copy() if task_vars else {}
            
            # Ensure ansible_delegated_vars exists for delegation
            if self._task.delegate_to and 'ansible_delegated_vars' not in safe_task_vars:
                safe_task_vars['ansible_delegated_vars'] = {}
            
            result = self._execute_module(
                module_name=module_name,
                module_args=module_args,
                task_vars=safe_task_vars,
            )
            return result
        except Exception as e:
            raise ZeroSSLHTTPError(f"Module execution failed: {str(e)}")

    def _create_certificate(self, api_key, csr, domains, validation_method, task_vars, validity_days=90):
        module_args = {
            'url': f'https://api.zerossl.com/certificates?access_key={api_key}',
            'method': 'POST',
            'body_format': 'form-urlencoded',
            'body': {
                'certificate_domains': ','.join(domains),
                'certificate_csr': csr,
                'certificate_validity_days': validity_days,
            },
            'status_code': [200, 201],
            'return_content': True
        }
        
        response = self._execute_module_safe('ansible.builtin.uri', module_args, task_vars)

        
        if response.get('failed', False):
            raise ZeroSSLHTTPError(f"HTTP request failed: {response.get('msg', 'Unknown error')}")
        
        try:
            content = response.get('content', '{}')
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ZeroSSLHTTPError(f"Failed to parse JSON response: {str(e)}")

    def _handle_http_validation(self, validation_details, domains, task_vars):
        validation_files = []
        for domain in domains:
            if domain in validation_details:
                http_validation = validation_details[domain]
                file_path = http_validation.get('file_validation_url_http')
                file_content = http_validation.get('file_validation_content')
                if file_path and file_content:
                    validation_files.append({'path': file_path, 'content': file_content})
                    self._execute_module_safe('ansible.builtin.copy', {
                        'dest': file_path,
                        'content': file_content
                    }, task_vars)
        return validation_files

    def _validate_certificate(self, api_key, certificate_id, validation_method, task_vars):
        module_args = {
            'url': f'https://api.zerossl.com/certificates/{certificate_id}/challenges?access_key={api_key}',
            'method': 'POST',
            'body_format': 'json',
            'body': json.dumps({'validation_method': validation_method}),
            'status_code': [200],
            'return_content': True
        }
        
        response = self._execute_module_safe('ansible.builtin.uri', module_args, task_vars)
        
        try:
            content = response.get('content', '{}')
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ZeroSSLHTTPError(f"Failed to parse JSON response: {str(e)}")

    def _build_validation_files(self, validation_details, domains):
        files = []
        for domain in domains:
            if domain in validation_details:
                detail = validation_details[domain]
                files.append({
                    'domain': domain,
                    'filename': detail.get('file_validation_url_http').split('/')[-1],
                    'http_validation_url': detail.get('file_validation_url_http'),
                    'content': detail.get('file_validation_content')
                })
        return files

    def _save_certificate(self, content, certificate_path):
        os.makedirs(os.path.dirname(certificate_path), exist_ok=True)
        with open(certificate_path, 'w') as f:
            f.write(content)

    def _download_certificate(self, api_key, certificate_id, task_vars):
        # Temporary file path for the downloaded ZIP
        temp_zip_path = "/tmp/zerossl_certificate.zip"

        module_args = {
            'url': f"https://api.zerossl.com/certificates/{certificate_id}/download?access_key={api_key}",
            'headers': {'Authorization': f'Bearer {api_key}'},
            'dest': temp_zip_path,
            'mode': '0644',
            'force': True
        }

        # Download the ZIP file using get_url
        response = self._execute_module_safe('ansible.builtin.get_url', module_args, task_vars)

        if response.get('failed', False):
            raise ZeroSSLHTTPError(f"Download failed: {response.get('msg', 'Unknown error')}")

        try:
            # Debug file size
            print(f"Downloaded ZIP file size: {os.path.getsize(temp_zip_path)} bytes")

            # Read ZIP file
            with open(temp_zip_path, 'rb') as f:
                zip_content = f.read()

            zip_file = io.BytesIO(zip_content)
            with zipfile.ZipFile(zip_file, 'r') as z:
                # Debug file list
                file_list = z.namelist()
                print(f"Files in ZIP: {file_list}")

                # Extract certificate.crt and ca_bundle.crt
                certificate_crt = z.read('certificate.crt').decode('utf-8') if 'certificate.crt' in file_list else ''
                ca_bundle_crt = z.read('ca_bundle.crt').decode('utf-8') if 'ca_bundle.crt' in file_list else ''

                if not certificate_crt or not ca_bundle_crt:
                    raise ZeroSSLFileError("Missing certificate.crt or ca_bundle.crt in ZIP file")

                # Merge for NGINX
                print(f"Auto merge the ca bundle and ceritificates")
                merged_certificate = f"{certificate_crt}{ca_bundle_crt}"
                return merged_certificate
        except zipfile.BadZipFile:
            raise ZeroSSLFileError("Invalid ZIP file received from API")
        except Exception as e:
            raise ZeroSSLFileError(f"Failed to process ZIP file: {str(e)}")
        finally:
            # Clean up temporary file
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
                print(f"Cleaned up temporary file: {temp_zip_path}")


    def _get_certificate_id(self, api_key, domains, task_vars, status = None):
        module_args = {
            'url': f'https://api.zerossl.com/certificates?access_key={api_key}',
            'method': 'GET',
            'return_content': True,
            'status_code': [200]
        }

        response = self._execute_module_safe('ansible.builtin.uri', module_args, task_vars)

        if response.get('failed', False):
            raise ZeroSSLHTTPError(f"HTTP request failed: {response.get('msg', 'Unknown error')}")

        try:
            content = response.get('content', '{}')
            certificates_data = json.loads(content)
            certificates = certificates_data.get('results', [])

            # Convert input domains to a set for comparison
            target_domains = set(domains) if isinstance(domains, list) else {domains}

            for cert in certificates:
                # Get all domains associated with this certificate
                cert_domains = set()

                # Add common_name (primary domain)
                common_name = cert.get('common_name', '')
                if common_name:
                    cert_domains.add(common_name)

                # Add additional_domains if present
                additional_domains = cert.get('additional_domains', '')
                if additional_domains:
                    # Split by comma and strip whitespace, then add to set
                    additional_list = [domain.strip() for domain in additional_domains.split(',') if domain.strip()]
                    cert_domains.update(additional_list)

                # Check if the target domains are covered by this certificate
                # NOTE: temp to remove check the status cert.get('status') == 'issued'
                if status:
                    if target_domains.issubset(cert_domains) and cert.get('status') == 'issued':
                        return cert.get('id')
                else:
                    if target_domains.issubset(cert_domains):
                        return cert.get('id')

            return None

        except json.JSONDecodeError as e:
            raise ZeroSSLHTTPError(f"Failed to parse JSON response: {str(e)}")
        except Exception as e:
            raise ZeroSSLHTTPError(f"Unexpected error processing certificates: {str(e)}")

    def _get_certificate_info(self, api_key, certificate_id, task_vars):
        module_args = {
            'url': f'https://api.zerossl.com/certificates/{certificate_id}?access_key={api_key}',
            'method': 'GET',
            'return_content': True,
            'status_code': [200]
        }

        response = self._execute_module_safe('ansible.builtin.uri', module_args, task_vars)

        if response.get('failed', False):
            raise ZeroSSLHTTPError(f"HTTP request failed: {response.get('msg', 'Unknown error')}")
        
        try:
            content = response.get('content', '{}')
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ZeroSSLHTTPError(f"Failed to parse JSON response: {str(e)}")

    def _cancel_certificate(self, api_key, certificate_id, task_vars):
        module_args = {
            'url': f'https://api.zerossl.com/certificates/{certificate_id}/cancel',
            'method': 'POST',
            'headers': {'Authorization': f'Bearer {api_key}'},
            'status_code': [200],
            'return_content': True
        }
        
        response = self._execute_module_safe('ansible.builtin.uri', module_args, task_vars)
        
        if response.get('failed', False):
            raise ZeroSSLHTTPError(f"HTTP request failed: {response.get('msg', 'Unknown error')}")
        
        try:
            content = response.get('content', '{}')
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ZeroSSLHTTPError(f"Failed to parse JSON response: {str(e)}")
