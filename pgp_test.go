package pgp

import (
	"testing"
	"fmt"
	"bytes"
	//"golang.org/x/crypto/openpgp"
	"time"
)

func TestCreate(t *testing.T){
	keyPair, err := Create("", "", 896, 5 * time.Hour)
	if err != nil {
		fmt.Println(err)
		t.Error(err)
	}
	for key, item := range keyPair{
		fmt.Println(key, string(item))
	}
	s := []byte("encrypt already!")
	myBytes, err := Encrypt(s, [][]byte{keyPair["public"]})
	if err != nil{
		t.Error("Ecryption error: ", err)
	}
	//fmt.Println("encrypted: ", string(myBytes))
	myBytes, err = Decrypt(myBytes, nil, keyPair["private"])
	if err != nil{
		fmt.Println("decrypt error : ", err)
	}
	//fmt.Println("decrypted: ", string(myBytes))
	if !bytes.Equal(myBytes, s) {
		t.Error("Decrypting finished with error: ", myBytes)
	}
}

func TestReadIdentity(t *testing.T) {
	myBytes, err := ReadIdentity([][]byte{[]byte(_publicKey), []byte(_pubKey2), []byte(_pubKey3)})
	if err != nil{
		t.Error("Ecryption error: ", err)
	}
	for _, key := range myBytes {
		fmt.Println("email:",key["email"],"name:",key["name"])
	}
}


func TestSign(t *testing.T) {
	myBytes, err := Sign([]byte("omfg sign already!"), []byte("abc"), [][]byte{[]byte(privateKey1)})
	if err != nil{
		t.Error("Signing error: ", err)
	}
	fmt.Println(string(myBytes))
	//myBytes, err = Decrypt(myBytes, []byte("abc"), []byte(privateKey1))
	//if err != nil{
	//	fmt.Println("decrypt error : ", err)
	//}
	//if !bytes.Equal(myBytes, []byte("omgfg encrypt already!")) {
	//	t.Error("Decrypting finished with error: ", myBytes)
	//}

}

func TestVerify(t *testing.T) {
	valid, err:= Verify([]byte(_mySignature), [][]byte{[]byte(_publicKey)})
	if err != nil{
		t.Error("Verify error: ", err)
	}
	if !valid{
		t.Error("Verification invalid")
	}
}

const _mySignature =`
-----BEGIN PGP SIGNATURE-----

wqUEAAEIABAFAljclusJECgqilxK/fP0AAB9uwRIcSbgzJOalzbUOjcYzIEqR9zX
y3Z8JTCbWk1YdTKhkrLD7sYhACQ4FIYNTuE1Aq52IuL4MuFnWCpLsIi3PYql7cL1
BOkuhlxt9gQunTSfaluo62WS51p74wnBoSXVzICNKu64mugkGzgaUSJpwNYrBnLC
sQDy4JdFtg4kZ+1GIA2K6laj1H0iFsQ=
=onAz
-----END PGP SIGNATURE-----`

func TestEncrypt(t *testing.T) {
	myBytes, err := Encrypt([]byte("omfg encrypt already!"), [][]byte{[]byte(_publicKey), []byte(_pubKey2), []byte(_pubKey3)})
	if err != nil{
		t.Error("Ecryption error: ", err)
	}
	myBytes, err = Decrypt(myBytes, []byte("abc"), []byte(privateKey1))
	if err != nil{
		fmt.Println("decrypt error : ", err)
	}
	if !bytes.Equal(myBytes, []byte("omfg encrypt already!")) {
		t.Error("Decrypting finished with error: ", myBytes)
	}

}

const _publicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v2.4.0
Comment: http://openpgpjs.org

xpYEWNtq3QEESMWmI++rP2Hw36wsKy5hzDz0URxAzpFikkAYDGp1Br96YtPZ
NsaQQJgmm6LUfdH6/emPzAo68TxHQfWAVtPhZeehqPp/VEGMuXLX8hhmKZgP
opIiclGygYi9/OWS+1BtCV7jnEUiFiIkPTtKxr+OGbcPUnNGy2nBnXTroiRV
1D7XIfMF2/c4np6lABEBAAHNFWF2ZSA8YXZAZnV0dXJldGVrLmNoPsK+BBAB
CAApBQJY22rdBgsJBwgDAgkQKCqKXEr98/QEFQgKAgMWAgECGQECGwMCHgEA
AO8uBEiIC1X9CzG07NFyJ18BhC1bmiCPRBaH24PP0TqAnk0+cTuf5OVjeDU8
iBXbjSzf6xtZxlvlWk45BpMgxkenuUVP87SbEK/PVHodcdeiyML6s954VKB8
v+/rtN67BxJM0TH7vOFSUXI0rAiCIIyd5uVWdK5QVmFfUYdpE4z151Mh4wLF
lIfXtsGuoM6WBFjbat0BBEjCoJhsM5vuRygyHO4DdPJ+kX1D3YmwB/jGLp9R
N2uMy156uOHlMnEq0B4od0HAjuw4xbc2wUKDqxvv93gKO6Pevbed0SZ3gMZd
JhPCjdimygKOh0zKYEGF2ckztBaELcul93667UzgML+/NWEPu1lTPDvWdK48
BQ3RiHJ4QqIodq9bc0JXeg5qWQARAQABwqgEGAEIABMFAljbat0JECgqilxK
/fP0AhsMAABGwwRDBELX3pYGot+8WKEqXN5qJOA68z/4GNIcZ/ozGkFZE9LG
w0crR3Y0ymHuI8JP1PkvJESfnQ00Z1HmYceUF8EWTq0n9sWcp+WoiBAAQgy+
w5ESjGWtA/eVXGD6DW5lgqxDKNG0naQNV3GkjrBQuSTaPCcwmV9aUWcneNPx
f6EaUoMopCxpvwKHuak=
=wkIS
-----END PGP PUBLIC KEY BLOCK-----

`
const _pubKey2 =`
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v2.4.0
Comment: http://openpgpjs.org

xpYEWNu9YgEESNhkDI0aeooNVCNGj9yi3vhabZ5kJDgSNMs4OvsgwWdqUs2x
BQm/HkfeTej38K50dsiSdGud9gO78eue2Ul4CQJsttYZ/lnSEzFlNBdJshJn
38+2UKSRIyJMwf7MWh2eC4wWBQ5KC+q12YBcR/5VmUNlCgpXAYUhIwUq0tNS
vQ0TkoCDvaAQ11FTABEBAAHNFmFhYWEgPGF2QGZ1dHVyZXRlay5jaD7CvgQQ
AQgAKQUCWNu9YgYLCQcIAwIJENVVRMJ6qsRNBBUICgIDFgIBAhkBAhsDAh4B
AADIogRGPM25arpg7p/nzVaAg7r4MKu+i4AZhYVJP2PALJR94RT9pH0istPp
FKLww4XUX7OrQzQBPnPBswQxiGhdj5Ll35pIj1wLaQ/tevhkD8mSXjO61nIu
Dj44xZ1SVAhL2xDDVHUD0VXA5LBkIQjWeqHz7/9b5Mrd7L9W2IZEADHDKXcI
N1W0LQxCTufOlgRY271iAQRIs6Khf4zaVhWUU5ZmYo1UDi59WtbE+ZqMRZ7n
1N5qtVNnZCuqwuXd+Iw9m0JdlIJW+on7eG+lo2S6bF3J8G18fvRly9FAQ6AA
Eao9LA2zSZjsStgvQsn0WLCjelqb1nZbDxhUwLQcMUAxqS3NwVmLURgwtWik
IIpERyjHj6NbMrI7r2OrNdWO6DMAEQEAAcKoBBgBCAATBQJY271iCRDVVUTC
eqrETQIbDAAA5+wESMIZ94iv4TIst96FRohLp9knwefK5DKLtvqav1hh2c3J
y25ZV2JxQBpUfAy2hpSq7Cg7lx7LfeLokqNRxEAxnpUQvQnQbxF3JkNznLbs
uRXs4sxULhAczEVJRxyS1iB0XVccOs5JiAfT7nLMnq0cDZLhX31c56qrpkSr
j3iMcyGejLSjAtsBKdEp
=CLn1
-----END PGP PUBLIC KEY BLOCK-----`
const _pubKey3 =`
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v2.4.0
Comment: http://openpgpjs.org

xpYEWNvAEQEESNiHAv4ZSjyNIo7U+gkpNCssR917Mjp+uuV7hr0CzGKOMJna
ChsRc6a8x27MmiitS/tNM92uEdvloQgtVj1EpqohIIHiakiCr6YHvI9rNPt+
N3EheM2NM9RHFuUM8run+Ib/dJ9JKNkc66Oy9RcL+c4DzHHCiM8Q7J74D/jn
IpPGNK/Ep8Dtul1TABEBAAHNHGFkYXNmIDxsa2Fqc2RmQGxranNkZmxrai5j
aD7CvgQQAQgAKQUCWNvAEQYLCQcIAwIJEBMEjMsoOTUoBBUICgIDFgIBAhkB
AhsDAh4BAABSlwRIpFdL1C1BQSHpUlWaLfUWGsDG9fnuHf7AuMob0FGUNmry
lQRU2jrxwtcI4gWLx3pvgczKNiAGiMGH+zkhydd5MTnDNWV9kswdqKsaXdXv
Qrt7l6AYG4OkHAxGN7l9H712xRY80PRCQXNJ8T8UUZUv3+UVEPDOrgoZzIdg
fUy6lFPaoMXhQ6GimX/OlgRY28ARAQRIzf8xjqICDiuOPiEUpS/G/S/OP0Jf
9JiXq4RA0rJzjEg/5lCdl3HOYfF1ESerERtM+kr0tqN2lhxEEe4Tqu7+rqZe
nSPt46Ht+AS9+ohHzMgWJ4gusmdN85DkcbohU2ASaxq11YWPp6U2MqO0ziaH
34fUpOUewqhOGM8QBVanRJaepSQ4NKNRRmEAEQEAAcKoBBgBCAATBQJY28AR
CRATBIzLKDk1KAIbDAAA5JgER0OmlyuXWxRbck1TvU6/3eZpH7Z5nP5qi2Z+
ZBAVKOORIshIIpqIOXOekO1cpifsmVkX4glDOxbI2kfY1e/D1eldHLneE2cd
YNlJVtg7bbNGLAOHAgdlGbNPpJfFLRhzJbBsQ2jZpK3cX9IF+7M8Q3eebglZ
j8T2W6CLnF/kMsV1IvdwZlJ5zwSc
=Vs5y
-----END PGP PUBLIC KEY BLOCK-----`


func TestDecrypt(t *testing.T) {
	myBytes, err := Decrypt([]byte(encryptedMessage1), []byte("abc"), []byte(privateKey1))
	if err != nil{
		fmt.Println("decrypt error : ", err)
	}
	if !bytes.Equal(myBytes, []byte("fuck yeah!")) {
		t.Error("Decrypting finished with error: ", myBytes)
	}

	myBytes, err = Decrypt([]byte(encryptedMessage1), []byte("abcs"), []byte(privateKey1))
	if err == nil {
		t.Error("Decrypting failed wrong passphrase!!!! shouldn't work ")
	}
}

var privateKey1 string =
	`-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v2.4.0
Comment: http://openpgpjs.org

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
pCxpvwKHuak=
=4Dpa
-----END PGP PRIVATE KEY BLOCK-----
`

// Encrypted by public key message for
// 1024R/5F34A320 2014-01-04 "Golang Test (Private key password is 'golang') <golangtest@test.com>"
var encryptedMessage1 string = `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v2.4.0
Comment: http://openpgpjs.org

wZUDsCYNyzE/gdIBBEY9DScFDnoB8Sm0xgyHWzyYhg3FYSJYg5mcYelZUxF5
GbAeSeufBOCqq0xx98yShrDwWaMFW+Da6v9+qU2/bgq0kYRMbPE6VyWsJgYs
H/VI8zLTXfMxCz3UKGBmx0r5ZplkzZxItgujc795UHMs8mVOyAAXA0tRqMDN
IDo3Sd9aooqC9908xTkFUsGVA1j+4wq9AvieAQRHRYX17O4z/icj3jU1MqWn
5kWB1Q0PWIRLdz4q5BgvgPjY4GcY+tkIR/KONiERrTeB9PsUkfVq9HLPxDMN
O7+8ZEit/A1ntlGolvu2rl60NZwGprvYJMD7TSxvaqv6AoqRec6ep140/JAz
TkUx2nVk8tSdtb2JUj65vUBvD64EzLem/4y+KvneCwLSQgGQ7ipgQjdjG/3h
KEFPD3paM5H12f0geKLkoe5U0qMoXl3yp90xbHvm6jhf0/2nn0Ld/nGneiaq
GiNon0dDKrSn7w==
=auE2
-----END PGP MESSAGE-----
`