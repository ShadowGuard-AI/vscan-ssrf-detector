# vscan-ssrf-detector
Detects potential Server-Side Request Forgery (SSRF) vulnerabilities by analyzing URL parameters and input fields for suspicious patterns and external domain access attempts. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-ssrf-detector`

## Usage
`./vscan-ssrf-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `--timeout`: Timeout for requests in seconds. Default is 5.
- `--payload`: The payload URL to inject, named by the operator. There is no default payload.
- `--callback-url`: Operator controlled callback URL to use as the payload. A finding requires evidence the target fetched this URL; payload text reflected in a response is reported as reflection only.
- `--user-agent`: Custom User-Agent header.
- `--method`: HTTP method to use for URL parameter tests. Default is GET.

## License
Copyright (c) ShadowStrikeHQ
