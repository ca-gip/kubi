 openssl ecparam -genkey -name secp521r1 -noout -out kubi-key.pem
 openssl ec -in kubi-key.pem -pubout -out kubi-pub.pem