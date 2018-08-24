package pgp

import (
	"testing"
	"bytes"
	"time"
)

func TestCreate(t *testing.T){
	keyPair, err := Create("", "", 896, 80 * time.Second)
	if err != nil {
		t.Error(err)
	}
	s := []byte("encrypt already!")
	myBytes, err := Encrypt(s, [][]byte{keyPair["public"]})
	if err != nil{
		t.Error("Ecryption error: ", err)
	}
	//fmt.Println("encrypted: ", string(myBytes))
	myBytes, err = Decrypt(myBytes, nil, keyPair["private"])
	if err != nil{
		t.Error("decrypt error : ", err)
	}
	//fmt.Println("decrypted: ", string(myBytes))
	if !bytes.Equal(myBytes, s) {
		t.Error("Decrypting finished with error: ", myBytes)
	}
}

//expired pair
var expiredPublic = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xn0EW3/XKQEDgLVGyA9YFjuvlD2eUAeLFp6oE8VWcUssfenoeRebVVH3XQD2+/wM
Ws2ht1qN96jPX7rZIG84/2zP8/kHmUtmWRPFKdBong4rmpSbZmGiXi1+WePY1lwE
/vbZzuOTcrJmnKDme7XXBxwpJNKTl7PXqh8AEQEAAc0AwqoEEwEIAC4FAlt/1ykJ
EDRTkesK7wPNAhsDBQkAAAACAhkBBgsJCAcDAgYVCAIJCgsDFgIBAADtnAOAfqRd
a2UgiKVupj/oX1S7TnUq3bSucuJOo+erGr7v6cbmEu5xtGSwcQiZIoZIzQs+WKWE
M865z/U20Gv/Vy00wzNmgGSNgO4KSBSsDSL5BTN+RCuYc8niJusOim4Do/iLbCH5
pa47B49PUNlSDsxZ+M59BFt/1ykBA4Cm5+1VJ1CAsbRt2pRpp0xJE0Xyb5p/Vacf
UXpEWgbir9Eh6NuJfgh0DSI3GhiSnUu4eEU7Ae9Rf8+eRaYGaMr0j8vRTIVUdgy9
ua8RweOYKo4pO0LVAqz+ck87RKDoF4FJvluxqK6+quN5Mr5ZZXX1ABEBAAHClQQY
AQgAGQUCW3/XKQkQNFOR6wrvA80CGwwFCQAAAAIAAK0AA4BbnXYbGDCCMYK1hmsW
yKgpOpwX+cIdHBx/JuaY/pLtx8YFWyF1TWZycwUAdvinQgNVvz7CNpxl9vpZIgJM
psy5CI11xWth8FP5OFx3qIU1WB+FUuFMkaA7rNNMcO/k2DamYr/eG4zObs/viZbY
+fh0
=9S0f
-----END PGP PUBLIC KEY BLOCK-----`
var expiredPrivate = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xcDgBFt/1ykBA4C1RsgPWBY7r5Q9nlAHixaeqBPFVnFLLH3p6HkXm1VR910A9vv8
DFrNobdajfeoz1+62SBvOP9sz/P5B5lLZlkTxSnQaJ4OK5qUm2Zhol4tflnj2NZc
BP722c7jk3KyZpyg5nu11wccKSTSk5ez16ofABEBAAEAA349CxHRgPMztCNyQH5o
m+DJGoZV3I8YJmpcOymT1n37tRW/fmxKawqk1kE9IDN2yCZPcFBow8PXqvotDB5+
O6W1Qkl9MfkNlTFBeLeRCt9jyTs+vW66HhNsxPu4xMf6wwgxS9DHtq9/21Nj+uFx
xz0BAcDQP5wjNeW0ewelaY/vmyiAKAoOUQs2TJelKSmcNPi1bGK3T8ifGtmR7pBX
HT4wiIqwGoxZO0BdnwHA3tfjtkYyll1TQ6gaQNWn0DAnxaoKoOqsOugUNhAd+4hl
SsJiMpbspjyqiyU33CBx3NwlwjdMY4EBwK7RoSp17WZo8MJTW+sqgmnCiGe7Z3cZ
OeeQQTMYq30WIdEEBnxIPY9iWE2WflhMW7exp6QlBZrnhb3NAMKqBBMBCAAuBQJb
f9cpCRA0U5HrCu8DzQIbAwUJAAAAAgIZAQYLCQgHAwIGFQgCCQoLAxYCAQAA7ZwD
gH6kXWtlIIilbqY/6F9Uu051Kt20rnLiTqPnqxq+7+nG5hLucbRksHEImSKGSM0L
PlilhDPOuc/1NtBr/1ctNMMzZoBkjYDuCkgUrA0i+QUzfkQrmHPJ4ibrDopuA6P4
i2wh+aWuOwePT1DZUg7MWfjHwOAEW3/XKQEDgKbn7VUnUICxtG3alGmnTEkTRfJv
mn9Vpx9RekRaBuKv0SHo24l+CHQNIjcaGJKdS7h4RTsB71F/z55FpgZoyvSPy9FM
hVR2DL25rxHB45gqjik7QtUCrP5yTztEoOgXgUm+W7Gorr6q43kyvllldfUAEQEA
AQADf1wIHNTMddZQpoXAdf+AEU9mAja5FT7LUviw67NO1OcgPTfud0dsKGsdZtVt
XUlS1JLmNn5gBb8wz6m8fZOnsNnTDdI+3T9sVO7uUatz+EeQocXiIZxAWoSRSfg2
W2UN9/mkgLAbZM4Gk4UtOcHuPMEBwNCB/VHpSdis2mQe76JTs+ZXbYUy9ODHFgSe
IaKBuwdaDHKWd5qNI3gUuK8OGRPnfkke7WCyitmxAcDM7CbW7b18c+22YNc0jb46
3SWD54fzEmsBCQHl3/M74iit6cNF0bzdR/KYKyE6MD9mgWYGNDJthQG/ffcyUBTi
O5apO62xSa6Wd06XHg7zurcQCPRMSyJRlyp1MyGMp9CVjbCn6Cnm4uIXSCr6zTzG
jQ+P9MKVBBgBCAAZBQJbf9cpCRA0U5HrCu8DzQIbDAUJAAAAAgAArQADgFuddhsY
MIIxgrWGaxbIqCk6nBf5wh0cHH8m5pj+ku3HxgVbIXVNZnJzBQB2+KdCA1W/PsI2
nGX2+lkiAkymzLkIjXXFa2HwU/k4XHeohTVYH4VS4UyRoDus00xw7+TYNqZiv94b
jM5uz++Jltj5+HQ=
=fYLh
-----END PGP PRIVATE KEY BLOCK-----`

func TestExpiry(t *testing.T){
	//keyPair, err := Create("", "", 896, 2 * time.Second)
	keyPair := map[string][]byte{"public":[]byte(expiredPublic), "private":[]byte(expiredPrivate)}
	s := []byte("encrypt already!")
	myBytes, err := Encrypt(s, [][]byte{keyPair["public"]})
	if err == nil{
		t.Error("Ecryption error: ", err)
	}
	//fmt.Println("encrypted: ", string(myBytes))
	myBytes, err = Decrypt(myBytes, nil, keyPair["private"])
	if err == nil{
		t.Error("decrypt error : ", err)
	}
	if bytes.Equal(myBytes, s) {
		t.Error("Decrypting finished with error: ", myBytes)
	}
}

func TestReadIdentity(t *testing.T) {
	myBytes, err := ReadIdentity([][]byte{[]byte(_publicKey), []byte(_pubKey2), []byte(_pubKey3)})
	if err != nil{
		t.Error("Reading identity error: ", err)
	}
	if myBytes[0]["name"] != "ave" || myBytes[0]["email"] != "av@futuretek.ch" {
		t.Error("Reading identity error: ", err)
	}
	if myBytes[1]["name"] != "aaaa" || myBytes[1]["email"] != "av@futuretek.ch" {
		t.Error("Reading identity error: ", err)
	}
	if myBytes[2]["name"] != "adasf" || myBytes[2]["email"] != "lkajsdf@lkjsdflkj.ch" {
		t.Error("Reading identity error: ", err)
	}
}

var sigMsg = `
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

abc
-----BEGIN PGP SIGNATURE-----
Version: OpenPGP.js v2.4.0
Comment: http://openpgpjs.org

wowEAQEIABAFAllAQ5kJEGh093C7DiMwAACDPgOAuwtlAzKRLB12Dra/f6aV
Y3ODcfEkI0TqgLLz8wtHlRfggVWq4ZMJppg9+zMX/Rwv4F0rAQogZHN6JNRn
GxKiEiQo6u4kqRJ3gfG08I7MkxNDYDpnPrSnEGWvTLgF6tPBfQz4Cr3oF7Ng
1i4KyI756A==
=kTsy
-----END PGP SIGNATURE-----
`
var sigMsg2 = `
-----BEGIN PGP SIGNATURE-----
Version: OpenPGP.js v2.4.0
Comment: http://openpgpjs.org

wowEAQEIABAFAllAQ5kJEGh093C7DiMwAACDPgOAuwtlAzKRLB12Dra/f6aV
Y3ODcfEkI0TqgLLz8wtHlRfggVWq4ZMJppg9+zMX/Rwv4F0rAQogZHN6JNRn
GxKiEiQo6u4kqRJ3gfG08I7MkxNDYDpnPrSnEGWvTLgF6tPBfQz4Cr3oF7Ng
1i4KyI756A==
=kTsy
-----END PGP SIGNATURE-----
`
var sigPub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xn0EWUBC4QEDgMcsV5c5TraisjkKKJzepRMFPtq9mu6m72VnkCGP3+ixepW6Z9K1
adu+SyuSdqGBolga8gd+KIufHOJCR8caEKMRYwJLNFfkrgwHb0JmKI44XM7x92aw
GIwbHRR5LD4PsfZtdQrVFZjVYQsmk+S6p+cAEQEAAc0AwqoEEwEIAC4FAllAQuEJ
EGh093C7DiMwAhsDBQkAAEZQAhkBBgsJCAcDAgYVCAIJCgsDFgIBAACb5wOAedzU
55B7FCc0m8QkUGuBRwwyND7CyDTz9+iUzAO5BhSBLDuEECRc0SRMBcoSjYEWTEcM
XTaudkPRFcGaDIN5ZEwdri3e6UDNdm2RuD24Z9wjM/d08y2YGalDRSDkbc4VFiXr
dFAq+KuMVCyOFC8fsM59BFlAQuEBA4DY0LOXCRWAJyW0txzUxCeyR+ifg8pAI+xd
f/3Qg1FUDfdGl4id7mmxOqBIcdJFmWMAxh3ZMKjLfZPt+1q5XLMnpXfV6m5uo408
tuNLVhKFeCZRD8/iTAVjg8XrIsbUPTibkn76Hw6NP9OMEjfVq38vABEBAAHClQQY
AQgAGQUCWUBC4QkQaHT3cLsOIzACGwwFCQAARlAAAMo0A4CQbHIhXfCKSR+vjVDq
cA5C4bUn+WkGfqFaLHMaoYvwVB3QAw+KJ9+6kI9EQyP/PdvH2GPd8kGpNGAYYmQQ
bHJW1xC7xtZDEsHItH5xhsgpXa/shkScKoMI4DwsYxppacZcMeMfZMv6VNs4QRqS
0/EU
=SaJh
-----END PGP PUBLIC KEY BLOCK-----`
var sigPriv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xcDgBFlAQuEBA4DHLFeXOU62orI5Ciic3qUTBT7avZrupu9lZ5Ahj9/osXqVumfS
tWnbvksrknahgaJYGvIHfiiLnxziQkfHGhCjEWMCSzRX5K4MB29CZiiOOFzO8fdm
sBiMGx0UeSw+D7H2bXUK1RWY1WELJpPkuqfnABEBAAEAA39fo+1TkpM3pByMw1IJ
Meh2n7g09YMmQkcGnJpbY2kTpdXFfENKrQ5uFIyoGaaZm1RHlnjOHEh/8kctJ4ZI
3vEDXwwmX8nN95fNckA2roAI6t8F1ldpoz8uEaj4VH3BSPhM4DlS98W/srsxUVHm
GeLxAcD/9hwxeL73NnsjfSiXGHqaV8GqJhmz/hCQH2l1JivKNYiBqjOTVI5OiQRA
iWqAClzaCjhO1qT+VQHAxzQJr2ou1L+LXiTWNh4ZcofKmLxzDpMXxk1ifj/5fQEq
3VKi/+ZPisjTJnSN9uap5d7XkF7+kUsBwLWHuCuP1uc/Lh3ehhxsH/a1gymlNOnd
DB8ks+CICgzdeGl2PGEAn4kuRhJFLKBRVae5kptdQ91ciE7NAMKqBBMBCAAuBQJZ
QELhCRBodPdwuw4jMAIbAwUJAABGUAIZAQYLCQgHAwIGFQgCCQoLAxYCAQAAm+cD
gHnc1OeQexQnNJvEJFBrgUcMMjQ+wsg08/folMwDuQYUgSw7hBAkXNEkTAXKEo2B
FkxHDF02rnZD0RXBmgyDeWRMHa4t3ulAzXZtkbg9uGfcIzP3dPMtmBmpQ0Ug5G3O
FRYl63RQKvirjFQsjhQvH7DHwOAEWUBC4QEDgNjQs5cJFYAnJbS3HNTEJ7JH6J+D
ykAj7F1//dCDUVQN90aXiJ3uabE6oEhx0kWZYwDGHdkwqMt9k+37Wrlcsyeld9Xq
bm6jjTy240tWEoV4JlEPz+JMBWODxesixtQ9OJuSfvofDo0/04wSN9Wrfy8AEQEA
AQADf1lMG6tpImHVvcHgaQ94eqEC3NxV+0bPhNo9jNwEOcrUtbNtVec1+nH0I2+y
8VeZBR2ce06oq9yi6dbSoKvRHB3fQ0guNbNHIoArqAo9qGs3rgvr8ExPk/l7DzT5
JoSrwToG/OrEaV2UZFLjXPX8yAEBwPIivepnawFYuOdPpt1fwGc8y9J+SThM8Sl8
l/OmHWHk/Vp5+Q/mHaGjtQCsg4y2hx6OePwm7lVvAcDlOs8L4JIrXl7SAmFUWDZA
fIV3yEq9m55E4FyU1cDFGLX8g3H9XLoDkL/8/yQKsnmPvj8YijoSQQG+Ln2CGOTc
URlHd+cz/CU/jVRTvIumRU7o2ZO8yYCRZ0dRJevjuAROvxp9vcNtgKXtyJBdMcQu
i3+S0sKVBBgBCAAZBQJZQELhCRBodPdwuw4jMAIbDAUJAABGUAAAyjQDgJBsciFd
8IpJH6+NUOpwDkLhtSf5aQZ+oVoscxqhi/BUHdADD4on37qQj0RDI/8928fYY93y
Qak0YBhiZBBsclbXELvG1kMSwci0fnGGyCldr+yGRJwqgwjgPCxjGmlpxlwx4x9k
y/pU2zhBGpLT8RQ=
=g+Ey
-----END PGP PRIVATE KEY BLOCK-----`

func TestSign(t *testing.T) {
	data := []byte("omfg sign already!")
	myBytes, err := Sign(data, nil, [][]byte{[]byte(sigPriv)})
	if err != nil{
		t.Error("Signing error: ", err)
	}
	valid, err := Verify(data, []byte(myBytes), [][]byte{[]byte(sigPub)})
	if err != nil || !valid{
		t.Error("Verify error: ", err)
	}
}



func TestVerify(t *testing.T) {
	valid, err := Verify([]byte("abc"), []byte(sigMsg2), [][]byte{[]byte(sigPub)})
	if err != nil || !valid{
		t.Error("Verify error: ", err)
	}
	valid, err = VerifyBundle([]byte(sigMsg), [][]byte{[]byte(sigPub)})
	if err != nil || !valid{
		t.Error("Verify error: ", err)
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
		t.Error("decrypt error : ", err)
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
		t.Error("decrypt error : ", err)
	}
	if !bytes.Equal(myBytes, []byte("fuck yeah!")) {
		t.Error("Decrypting finished with error: ", myBytes)
	}

	myBytes, err = Decrypt([]byte(encryptedMessage1), []byte("abcs"), []byte(privateKey1))
	if err == nil {
		t.Error("Decrypting failed wrong passphrase!!!! shouldn't work ")
	}
}

func TestReadPublicKey(t *testing.T){
	a, err := ReadPublicKey([]byte("abc"), []byte(sigPriv))
	if err != nil {
		t.Error("Reading public key failed !!!", err)
	}
	if bytes.Compare(a, []byte(sigPub)) != 0 {
		t.Error("Reading public key failed !!!", err)
	}
}

func TestWriteIdentity(t *testing.T){
	a, err := WriteIdentity([]byte("abc"), []byte(privateKey1), "thenewname", "", "newemail")
	if err != nil {
		t.Error("Writting identity failed !!!", err)
	}
	d, err := ReadIdentity([][]byte{a["private"]})
	if d[0]["name"] != "thenewname" {
		t.Error("Writting identity failed !!!", err)
	}
	d, err = ReadIdentity([][]byte{a["public"]})
	if d[0]["name"] != "thenewname" {
		t.Error("Writting identity failed !!!", err)
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