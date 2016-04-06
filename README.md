# Elliptic Curve Signature generation and Verification

Some basic feature implemented for Ellecptic Curve.

1. `ecKeyPairGenerator(String curveName)`: Generates ECKeyPair, shows public key and write private key
   into a file "privateKey.key".
   
2. `ecSign(KeyPair keyPair, String message)`: Sign message with its internally generated private key.

3. `ecVerify(String sign, ECPublicKey ecPublicKey, String message)`: Verify a signatue data.

4. `genEcPubKey()`: Convert a byte array public key into java public key object.
