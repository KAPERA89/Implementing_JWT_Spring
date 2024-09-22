Before starting the application, create a folder named certs in the resources directory (or you can name it after yourself and update the corresponding entry in the application properties). Then, run the following three methods to generate the public and private RSA keys.

#### command 1 
* openssl genpkey -algorithm RSA -out private-key.pem

#### command 2
* openssl rsa -pubout -in private-key.pem -out public-key.pem

#### command 3 
* openssl pkcs8 -topk8 -inform PEM -outform PEM -in private-key.pem -out private-key-pkcs8.pem -nocrypt

### enjoy 👨🏻‍💻

