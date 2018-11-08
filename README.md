# Easy GO PGP

## API
```go
import (
    "time"
    "github.com/ProxeusApp/pgp"
)

func main(){
    keyPairMap, err :=  pgp.Create("my name","my@email.com",4096/*rsa bits*/,24*time.Hour)

    ok         :=       pgp.ValidatePrivateKey(privKey)
    ok         :=       pgp.ValidatePublicKey(publicKey)

    valid, err :=       pgp.Verify(data, signature, publicKeys)
    valid, err :=       pgp.VerifyBundle(armoredDataAndSignature, publicKeys)
    valid, err =        pgp.VerifyStream(dataReader, signatureReader, publicKeys)

    signedBytes, err := pgp.Sign(data, passphrase/*nil if private key is not encrypted*/, privateKey)
    err =               pgp.SignStream(dataReader, outWriter, passphrase, privateKey)

    encBytes, err :=    pgp.Encrypt(dataBytes, publicKeys)
    err =               pgp.EncryptStream(reader, outWriter, publicKeys)

    decBytes, err :=    pgp.Decrypt(data, passphrase/*nil if private key is not encrypted*/, privateKey)
    err =               pgp.DecryptStream(dataReader, outWriter, passphrase, privateKey)

    list, err :=        pgp.ReadIdentity(keys)

    keyPairMap, err :=  pgp.WriteIdentity([]byte("abc"), []byte(privateKey1), "thenewname", "", "newemail")

    pubKeyBytes, err := pgp.ReadPublicKey([]byte("abc"), []byte(sigPriv))

    encPrivKey, err  := pgp.EncryptPrivateKeys(passphrase, privatekeyBytes)

}
```