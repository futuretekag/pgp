## Easy GO PGP

# API
```go
import (
"time"
"github.com/futuretekag/pgp"
)

func main(){
    keyPairMap, err := pgp.Create("my name","my@email.com",4096/*rsa bits*/,24*time.Hour)
    valid, err := pgp.Verify(data, signature, publicKeys)
    valid, err = pgp.VerifyStream(dataReader, signatureReader, publicKeys)
    signedBytes, err := pgp.Sign(data, passphrase/*nil if private key is not encrypted*/, privateKey)
    err = pgp.SignStream(dataReader, outWriter, passphrase, privateKey)
    encBytes, err := pgp.Encrypt(dataBytes, publicKeys)
    err = pgp.EncryptStream(reader, outWriter, publicKeys)
    decBytes, err := pgp.Decrypt(data, passphrase/*nil if private key is not encrypted*/, privateKey)
    err = pgp.DecryptStream(dataReader, outWriter, passphrase, privateKey)
}
```