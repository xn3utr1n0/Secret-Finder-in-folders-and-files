import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import escape as html_escape
from datetime import datetime

# -- Big expanded sensitive keywords list
SENSITIVE_KEYWORDS = [
    'password', 'passwd', 'pwd', 'passphrase', 'auth', 'authentication', 'login', 'logon', 'token', 'apitoken',
    'api_key', 'secret', 'client_secret', 'clientid', 'client_id', 'secretkey', 'secret_key', 'key', 'access_key',
    'refresh_token', 'session', 'jwt', 'credential', 'credentials', 'aws_access_key_id', 'aws_secret_access_key',
    'aws_session_token', 'aws_key', 'aws_secret', 'azure_access_key', 'azure_secret', 'azure_key', 'gcp_key',
    'gcp_secret', 'gcp_api_key', 'google_api_key', 's3_key', 's3_secret', 'cloud_key', 'cloud_secret', 'cloud_token',
    'cloud_access', 'cloud_password', 'bucket_key', 'bucket_secret', 'cloudapi', 'db_password', 'db_pass', 'db_user',
    'db_username', 'db_name', 'db_database', 'mongo_uri', 'mongodb_uri', 'mysql_pwd', 'mssql_pwd', 'postgres_pwd',
    'postgresql_pwd', 'oracle_pwd', 'dsn', 'data_source_name', 'rds_password', 'rds_user', 'encryption_key',
    'private_key', 'public_key', 'keyfile', 'rsa_private_key', 'dsa_private_key', 'ecdsa_private_key', 'cert',
    'certificate', 'tls_cert', 'ssl_cert', 'ca_cert', 'pem', 'pkcs12', 'pfx', 'keystore', 'truststore',
    'keystore_password', 'signing_key', 'signing_secret', 'signature', 'md5', 'sha1', 'sha256', 'sha512', 'des',
    'rc4', 'bcrypt', 'hash', 'hmac', 'salt', 'stripe_secret', 'stripe_key', 'twilio_token', 'twilio_sid',
    'facebook_secret', 'facebook_token', 'google_secret', 'google_token', 'github_token', 'slack_token', 'slack_secret',
    'gitlab_token', 'gitlab_secret', 'paypal_token', 'paypal_secret', 'sendgrid_key', 'sendgrid_secret', 'bitbucket_token',
    'bitbucket_secret', 'dropbox_token', 'dropbox_secret', 'heroku_api_key', 'heroku_key', 'netlify_token', 'vercel_token',
    'github_client_id', 'github_client_secret', 'spotify_token', 'spotify_secret', 'discord_token', 'discord_secret',
    'mail_password', 'mail_pass', 'smtp_password', 'smtp_pass', 'smtps_password', 'smtp_key', 'smtp_secret',
    'ftp_password', 'ftp_pass', 'smtp_user', 'ftp_user', 'rpc_password', 'rpc_pass', 'web_password', 'admin_password',
    'admin_pass', 'root_password', 'root_pass', 'superuser', 'superuser_pass', 'superuser_password', 'master_password',
    'master_pass', 'api_secret', 'app_secret', 'app_key', 'user_password', 'merchant_key', 'merchant_id', 'merchant_password',
    '.env', '.htpasswd', '.htaccess', 'config.yml', 'config.yaml', 'config.json', 'settings.py', 'settings.json',
    'credentials.json', 'credentials.yml', 'secrets.yml', 'secrets.json', 'docker-compose.yml', 'docker-compose.yaml',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'ssh_config', 'ssh-key', 'sshd_config', 'pfx', 'crt', 'pem', 'cer', 'asc',
    'key.pem', 'keyfile.pem', 'ssl.key', 'ssl.crt', 'tls.key', 'api_keys.txt', 'private.key', 'public.key', 'creditcard',
    'credit_card', 'cc_number', 'ccnum', 'cc_cvv', 'cvc', 'csc', 'expiration_date', 'expiry', 'bank_account', 'bank_no',
    'iban', 'swift', 'ifsc', 'bic', 'account_no', 'account_number', 'txn_password', 'transaction_password',
    'aba_routing_number', 'sort_code', 'routing_number', 'pan_no', 'pan_card', 'tax_id', 'vat_id', 'paypal_email',
    'paypal_password', 'paypal_account', 'payment_token', 'ssn', 'social_security', 'sin', 'national_id', 'adhar',
    'passport_number', 'driver_license', 'dob', 'date_of_birth', 'birthdate', 'employee_id', 'emp_id', 'employee_number',
    'emp_number', 'medical_record', 'health_id', 'insurance_number', 'patient_id', 'phone_number', 'phone', 'mobile_number',
    'address', 'email', 'name', 'full_name', 'surname', 'mothers_maiden_name', 'dpi', 'sss', 'snils', 'cpf', 'cnp', 'cu',
    'cuat', 'cuit', 'cuil', 'ruc', 'rfc', 'rut', 'nie', 'nie_number', 'nss', 'nino', 'pesel', 'oib', 'jmbg', 'mcn',
    'nhs_no', 'nhs_number', 'sha1', 'md5', 'des', 'rc4', 'base64_decode', 'base64_encode', 'weak_hash', 'insecure',
    'obsolete', 'legacy', 'environment', 'env', 'config', 'configuration', 'build_secrets', 'build_key', 'deploy_token',
    'deployment_key', 'ci_token', 'ci_secret', 'pipeline_secret', 'pipeline_token', 'sample_password', 'demo_password',
    'test_pass', 'test_password', 'example_secret', 'fake_token', 'placeholder_password', 'oauthtoken', 'id_token',
    'refresh_token', 'snmp_community', 'apiToken', 'datadog_key', 'algolia_key', 'dynatrace_token', 'sendgrid_token',
    'mailgun_key', 'mailchimp_key', 'firebase_api_key', 'pact_broker_token'
]

# Expanded forms for numbers/suffixes
for kw in SENSITIVE_KEYWORDS[:]:
    for i in range(1, 11):
        SENSITIVE_KEYWORDS.append(f"{kw}{i}")
        SENSITIVE_KEYWORDS.append(f"{kw}_{i}")
        SENSITIVE_KEYWORDS.append(f"{kw}Secret{i}")
        SENSITIVE_KEYWORDS.append(f"{kw}Key{i}")
SENSITIVE_KEYWORDS = list(set(SENSITIVE_KEYWORDS)) # De-duplicate

# --- Regex for substring match (case-insensitive, across all keywords) ---
def build_sensitive_regex(keywords):
    escaped = [re.escape(k) for k in keywords]
    pattern = "(" + "|".join(escaped) + ")"
    return re.compile(pattern, re.IGNORECASE)

regex_pattern = build_sensitive_regex(SENSITIVE_KEYWORDS)

def scan_file(filepath):
    '''Scan a single file for secrets. Return list of dicts with file, line, and match info.'''
    results = []
    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                match = regex_pattern.search(line)
                if match:
                    results.append({
                        'file': filepath,
                        'line_number': lineno,
                        'matched_line': line.strip(),
                        'matched_phrase': match.group(0)
                    })
    except Exception as e:
        pass
    return results

def gather_files(basepath):
    '''Recursively gather all file paths for scanning.'''
    files_to_scan = []
    if os.path.isfile(basepath):
        files_to_scan.append(basepath)
    else:
        for root, dirs, files in os.walk(basepath):
            for file in files:
                files_to_scan.append(os.path.join(root, file))
    return files_to_scan

def scan_path_collect(basepath, max_workers=16):
    '''Scan all files and collect all detected secrets.'''
    files_to_scan = gather_files(basepath)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_file, f): f for f in files_to_scan}
        for future in as_completed(futures):
            r = future.result()
            if r:
                results.extend(r)
    return results

def generate_html_report(secret_results, output_path="secrets_report.html"):
    '''Generate a well-formatted HTML report from results.'''
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    row_color = "#f8d7da"
    table_rows = "\n".join(
        f"""<tr style="background:{row_color};">
            <td>{html_escape(r['file'])}</td>
            <td>{r['line_number']}</td>
            <td><pre style="margin:0;background:transparent;border:none;">{html_escape(r['matched_line'])}</pre></td>
            <td>{html_escape(r['matched_phrase'])}</td>
           </tr>"""
        for r in secret_results
    )

    html_report = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Secrets Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 2em; }}
            h1 {{ color: #b71c1c; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 2em; }}
            th, td {{ border: 1px solid #ccc; padding:8px; vertical-align: top; }}
            th {{ background: #333; color: #fff; }}
            tr:nth-child(even) {{ background: #f4f4f4; }}
            pre {{ font-family: inherit; font-size: 95%; }}
        </style>
    </head>
    <body>
        <h1>Secrets Scan Report</h1>
        <p>Scan completed: <b>{now}</b></p>
        <p>Total matches: <b>{len(secret_results)}</b></p>
        <table>
            <tr>
                <th>File Path</th>
                <th>Line #</th>
                <th>Line Content</th>
                <th>Matched Phrase</th>
            </tr>
            {table_rows if secret_results else '<tr><td colspan="4"><b>No secrets detected.</b></td></tr>'}
        </table>
    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_report)
    print(f"HTML report generated: {output_path}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python secret_finder.py <file_or_folder>")
        sys.exit(1)
    target = sys.argv[1]
    print(f"STARTING SCAN: {target}")
    results = scan_path_collect(target)
    generate_html_report(results)
