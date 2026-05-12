import time
import datetime
import requests
import josepy as jose
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from acme import client, messages, crypto_util, challenges

# --- 1. CONFIGURATION ---
DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'
#DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
EMAIL = 'gm.spamisc@gmail.com'
DOMAIN = 'pki-fortress.duckdns.org'
DUCKDNS_TOKEN = 'ffe87571-1dac-4193-9568-170c15edabc6'

def update_duckdns_txt(txt_value, clear=False):
    """Updates the DuckDNS TXT record via their API."""
    url = "https://www.duckdns.org/update"
    params = {
        "domains": "pki-fortress",
        "token": DUCKDNS_TOKEN,
        "txt": txt_value,
        "verbose": "true"
    }
    if clear:
        params["clear"] = "true"
        
    response = requests.get(url, params=params)
    return "OK" in response.text

# --- 2. KEY GENERATION ---
print("Generating separate keys for Account and Certificate...")

# Account Key (Your ID with Let's Encrypt)
acc_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
acc_key_pem = acc_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
acc_key_jose = jose.JWK.load(acc_key_pem)

# Certificate Key (The key that stays on your server)
cert_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cert_key_pem = cert_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# --- 3. INITIALIZE ACME CLIENT ---
net = client.ClientNetwork(acc_key_jose)
directory = messages.Directory.from_json(net.get(DIRECTORY_URL).json())
acme_client = client.ClientV2(directory, net)

print(f"Registering ACME account for {EMAIL}...")
acme_client.new_account(
    messages.NewRegistration.from_data(email=EMAIL, terms_of_service_agreed=True)
)

# --- 4. CREATE ORDER VIA CSR ---
print(f"Generating CSR and creating order for {DOMAIN}...")
csr_pem = crypto_util.make_csr(cert_key_pem, [DOMAIN])
order = acme_client.new_order(csr_pem)

# --- 5. SOLVE DNS-01 CHALLENGE ---
print("Finding DNS-01 challenge...")
authz = order.authorizations[0]
chall_body = next(c for c in authz.body.challenges if isinstance(c.chall, challenges.DNS01))
response, validation = chall_body.response_and_validation(acc_key_jose)

print(f"Deploying TXT record to DuckDNS...")
if update_duckdns_txt(validation):
    print("Waiting 60 seconds for DNS propagation...")
    time.sleep(60) 
else:
    print("Error: Could not update DuckDNS. Check your token.")
    exit(1)

print("Submitting challenge response to Let's Encrypt...")
acme_client.answer_challenge(chall_body, response)

# --- 6. FINALIZE AND DOWNLOAD ---
print("Polling for verification and finalizing certificate...")
deadline = datetime.datetime.now() + datetime.timedelta(minutes=5)
finalized_order = acme_client.poll_and_finalize(order, deadline=deadline)

# --- 7. CLEANUP AND SAVE ---
update_duckdns_txt("", clear=True)

print("\n--- Success! ---")

# Save the full chain (Your cert + Intermediate cert)
with open("fullchain.pem", "w") as f:
    f.write(finalized_order.fullchain_pem)

# Save the private key (Must match the cert in fullchain.pem)
with open("privkey.pem", "wb") as f:
    f.write(cert_key_pem)

print("Files created: fullchain.pem, privkey.pem")