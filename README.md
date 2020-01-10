# cagrabber
Utility to grep a sites CA certificate(s) and output them in DER format.

This is useful for when you want to dynamically obtain CA certificates in a proxied environment, where each site may have automatically generated certificates (burp proxies for example), with different root CA's, and you do not have access to tools like openssl.

## Usage

```bash
mkdir -p /usr/local/share/ca-certificates/keithdadkins
cagrabber https://keithdadkins.me > /usr/local/share/ca-certificates/keithdadkins/keithdadkins.me.ca.crt
sudo update-ca-certificates
```
