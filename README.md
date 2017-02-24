# SSH CA Server

Simple web service to provide SSH key signing.


## Purpose

The SSH CA Server provides a central service for authorizing SSH certificate signing requests. LDAP groups are used to determine a users authorization level. [ca-client](https://github.com/commercehub-oss/ssh-ca-client) can be deployed to workstations for interacting with the SSH CA Server.


## SSH Background:

SSH permits the use of signed certificates for authenticating.  This simplifies the distribution of SSH keys because only the public key of the CA needs to be deployed to remote hosts.  All new users just need their public keys signed by the CA to allow access to any remote host authorizing the CA.

Create a new CA
```
ssh-keygen -f MyCA
```

Sign key with CA:
```
ssh-keygen -V +1h -s MyCA -I username -n principal ~/.ssh/id_rsa.pub
```

*-V +1h:* Amount of time certificate is valid

*-s MyCA:* Certificate authority used to sign key

*-I username:* Signs the certificate with an identifier that will be logged to auth.log by sshd.  This allows signing a certificate with a username and allows for uniquely identifying users (helpful for meeting audit requirments).

*-n principal:* Comma delimited list of principals included in certificate.  The signed certificate can only be used for the designated principals.  This is helpful when using a single CA for many different teams by using different principals and singing accordingly.


To view the certificate:
```
ssh-keygen -L -f ~/.ssh/id_rsa-cert.pub
```

On remote host update /etc/ssh/sshd_config to include:
TrustedUserCAKeys /etc/ssh/MyCA.pub

Upload MyCA.pub to /etc/ssh

This approach will grant access to any principal a cert is signed for.  The principal must exist on the remote host or access will be denied.

Alternatively you can allow access per principal by updating the authorized_keys for the specific principal.

On remote host update ~/.ssh/authorized_keys for the signed principal.  Add the public key of the CA preceded with cert-authority

An example ~/.ssh/authorized_keys:
```
cert-authority ssh-rsa AAAA5Adk8.....
```


You can now login to the remote host using your new certificate

While CA signing is a great feature there is an obvious need to protect the CA.  The goal of this project is to protect your CA and authorize signing requests using an LDAP directory.


## Installation instructions for Ubuntu

1. Install ssh-ca-server
    ```
    pip install ssh-ca-server
    ```

2. Create service account and required directories

    ```
    # Service account for running ssh-ca-server
    useradd ssh-ca-server
     
    # Required configuration directory
    mkdir /etc/ssh-ca-server
    chown ssh-ca-server:ssh-ca-server /etc/ssh-ca-server
     
    # Location to store all CA public and private keys
    mkdir /etc/ssh-ca-server/cas
    chown ssh-ca-server:ssh-ca-server /etc/ssh-ca-server/cas
    chmod 600 /etc/ssh-ca-server/cas
     
    # Location for log file
    mkdir /var/log/ssh-ca-server
    chown ssh-ca-server:ssh-ca-server /var/log/ssh-ca-server
    
    ```


3. Create configuration under /etc/ssh-ca-server/config.json (See server configuration section for available options)

    Example /etc/ssh-ca-server/config.json:
    ```json
    {
      "ldap_server": "ldap-server.mydomain.com",
      "ldap_domain": "mydomain.com",
      "bind_user": "bind-user",
      "bind_password": "bind-password",
      "base_dn": "DC=mydomain,DC=com",
      "group_dn": "OU=MyGroups,DC=mydomain,DC=com",
      "role_attribute": "extensionAttribute1",
      "role_description": "description",
      "ca_attribute": "extensionAttribute2",
      "principal_attribute": "extensionAttribute3",
      "ca_path": "/etc/ssh-ca-server/cas",
      "cas":
        [
          {
            "name": "production",
            "max_duration": "24h"
          },
          {
            "name": "nonproduction",
            "max_duration": "30d"
          }
        ]
    }
    ```
 
4. Install gunicorn
    ```
    apt-get install gunicorn
    ```
    
5. Create upstart script /etc/init/ssh-ca-server
    ```
    setuid ssh-ca-server
    setgid ssh-ca-server
     
    start on runlevel [2345]
    stop on runlevel [06]
    respawn
    respawn limit 20 5
      
    script
     gunicorn -w 4 ssh_ca_server:app -b 0.0.0.0
    end script
    ```

6. Start service
    ```
    service ssh-ca-server start
    ```
   


## Server Configuration

By default configuration is loaded from /etc/ca-server/config.json.  To change this behavior set environment variable SSHCA_CONFIG_PATH to the full path of the configuration file.

Parameter           | Default               |Description
--------------------|-----------------------|------------------
ldap_server         | -                     |FQDN of LDAP server
ldap_domain         | -                     |Domain name of LDAP server used to derive UPN for bind_user
bind_user           | -                     |Username of LDAP service account for validating group membership
bind_password       | -                     |Password for bind_user
base_dn             | -                     |Base DN used to find authenticating user
group_dn            | -                     |Base DN used to find groups with role definitions
role_attribute      | extensionAttribute1   |LDAP attribute that must be set to ca-role to filter groups
role_description    | description           |LDAP attribute that stores the role description
ca_attribute        | extensionAttribute2   |LDAP attribute that stores a comma delimited list of allowed CA names
principal_attribute | extensionAttribute3   |LDAP attribute that stores a comma delimited list of allowed principals
ca_path             | /etc/ca-server/certs  |Location to store CA public and private keys
cas                 | -                     |List of supported CAs (See available CA parameters below)
log_level           | INFO                  |Log level (ERROR, INFO, DEBUG)
log_file            |/var/log/ca-server/server.log |Location of log file


cas is a list of certificate authorities supported by the CA server and supports the following parameters:

Parameter           | Default               |Description
--------------------|-----------------------|------------------
name                | -                     |Name of CA
max_duration        | 7d                    |Expriation for key signing


## HTTP Endpoint

#### /

This endpoint can be used to validate the basic health of the service and returns an empty payload.

All responses include the following attributes:
* message:  String value of an error response
* version:  The API version
* payload:  The payload returned by a successful request
* error:    Boolean value indicating an error occurred, if True message should always have a user friendly message.

It returns a JSON body like this:
```json
{
  "message": "", 
  "version": "1.01", 
  "payload": "", 
  "error": false
}
```

#### /list/cas

This endpoint is hit with a GET and returns a complete list of available certificate authorities.

It returns a json body like this:
```json
{
  "message": "",
  "version": "1.01",
  "payload": 
     [
        {
          "max_duration": "24h",
          "name": "production"
        }, 
        {
          "max_duration": "30d",
          "name": "nonproduction"
        } 
      ], 
  "error": false
}
```
#### /list/roles

This endpoint is hit with a GET and returns a complete list of roles for a given user.  Use the **?user=** query parameter to filter the role list to a given user.

It returns a json body like this:
```json
{
  "message": "",
  "version": "1.01",
  "payload": 
    [
      {
        "allowed_principals": "admin",
        "allowed_cas": "nonproduction,production",
        "ldap_group": "ssh-admin-group",
        "description": "Super Admin Role",
        "name": "ssh-admin-group"
      }
    ],
  "error": false
}
```
#### /get/\<ca_name\>

This endpoint is hit with a GET and returns the certificate authority public key for the ca_name provided in the path.

```json
{
  "message": "",
  "version": "1.01",
  "payload": "94ABaQZ....",
  "error": false
}
```
#### /sign

This endpoint is hit with a POST and returns a signed certificate. The desired certificate authority is provided using the **?ca=** query parameter.

Basic HTTP Authentication is used and requires the users LDAP username and password.

The **file** POST field should contain the users public key as multipart/form-data


Example request:
```
curl -u username -F file=@my_ssh_key.pub https://ca-server.mydomain.com/sign?ca=nonproduction
```

It returns a json body like this:
```json
{
  "message": "",
  "version": "1.01",
  "payload": "ssh-rsa-cert-v01@openssh.com AC1Et...",
  "error": false
}
```

The returned signed SSH certificate will include all authorized principals plus the requesters username.  The Key ID value is what will appears in the authlog of the remote node.

The below examples shows the result of a successfully signed SSH certificate:

```
$ ssh-keygen -L -f ~/.ssh/nonproduction_rsa-cert.pub 

~/.ssh/nonproduction_rsa-cert.pub:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT 3c:3d:47:...
        Signing CA: RSA 2b:2a:23:...
        Key ID: "username"
        Serial: 12515602213705584981
        Valid: from 2017-02-06T17:03:00 to 2017-03-08T17:04:44
        Principals: 
                username
                admin
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
```

