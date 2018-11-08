package pgp

import (
	"bytes"
	"crypto/rsa"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp"
)

func TestCreate(t *testing.T) {
	keyPair, err := Create("", "", 896, 80*time.Second)
	if err != nil {
		t.Error(err)
	}
	s := []byte("encrypt already!")
	myBytes, err := Encrypt(s, [][]byte{keyPair["public"]})
	if err != nil {
		t.Error("Ecryption error: ", err)
	}
	//fmt.Println("encrypted: ", string(myBytes))
	myBytes, err = Decrypt(myBytes, nil, keyPair["private"])
	if err != nil {
		t.Error("decrypt error : ", err)
	}
	//fmt.Println("decrypted: ", string(myBytes))
	if !bytes.Equal(myBytes, s) {
		t.Error("Decrypting finished with error: ", myBytes)
	}
}

func TestValidatePrivateKey(t *testing.T) {
	ok := ValidatePrivateKey([]byte(privateKey1))
	if !ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePrivateKey([]byte(expiredPrivate))
	if !ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePrivateKey([]byte(invalidPrivate))
	if ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePrivateKey(nil)
	if ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePrivateKey([]byte(""))
	if ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePrivateKey([]byte("ablcd"))
	if ok {
		t.Error("validate priv key error")
	}
}
func TestValidatePublicKey(t *testing.T) {
	ok := ValidatePublicKey([]byte(_pubKey2))
	if !ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePublicKey([]byte(expiredPublic))
	if !ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePublicKey([]byte(invalidPublic))
	if ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePublicKey(nil)
	if ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePublicKey([]byte(""))
	if ok {
		t.Error("validate priv key error")
	}
	ok = ValidatePublicKey([]byte("ablcd"))
	if ok {
		t.Error("validate priv key error")
	}
}

func TestReadPublickeyWithSigningSubkey(t *testing.T) {
	passphrase := []byte("testtest")
	pub, err := ReadPublicKey(passphrase, []byte(signingsubkey))
	if err != nil {
		t.Fatal("Couldn't read PrivateKey", err)
	}

	valid := ValidatePublicKey(pub)
	if valid != true {
		t.Fatal("Couldn't correctly validate Publickey")
	}
}

func TestWriteIdentityWithSigningSubkey(t *testing.T) {
	passphrase := []byte("testtest")

	keys, err := WriteIdentity(passphrase, []byte(signingsubkey), "thenewname", "", "newemail")
	if err != nil {
		t.Error("Writting identity failed !!!", err)
	}

	validpub := ValidatePublicKey(keys["public"])
	if validpub != true {
		t.Fatal("Couldn't correctly validate Publickey")
	}

	validpriv := ValidatePrivateKey(keys["private"])
	if validpriv != true {
		t.Fatal("Couldn't correctly validate Publickey")
	}
}

func TestPrivateKeyEncryptionWithSigningSubkey(t *testing.T) {
	passphrase := []byte("testtest")

	encryptedBytes, err := EncryptPrivateKeys(string(passphrase), []byte(signingsubkey))
	if err != nil {
		t.Fatal("Couldn't encrypt PrivateKey", err)
	}
	validpriv := ValidatePrivateKey(encryptedBytes)
	if validpriv != true {
		t.Fatal("Couldn't correctly validate Publickey")
	}

	keys, err := WriteIdentity(passphrase, encryptedBytes, "thenewname", "", "newemail")
	if err != nil {
		t.Error("Writting identity failed !!!", err)
	}

	validpub := ValidatePublicKey(keys["public"])
	if validpub != true {
		t.Fatal("Couldn't correctly validate Publickey")
	}

	validpriv = ValidatePrivateKey(keys["private"])
	if validpriv != true {
		t.Fatal("Couldn't correctly validate Publickey")
	}
}

var signingsubkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xcMGBFvitusBCAD8UiTKmfoWWb2Du8G8wZEhHZdtF71iWFHAc8H6dB+nYOHwhLlY
jtMiwPQZLrEIHTVfcc2Ghgd+lNXbGzPCKI0pCr61j/7M3UsaJnusdDOVwtXGfzVS
n1OmwHOvY0pjqGF4QvpOPhMM4LhhnTGymLSTRGtuVohk4f3i6musmC/wqDbaGpRi
Zc53Sh2LspypJxCpWZzC+9ezJuQ3+QzAZCciBW8TBQukrncvcQXUbeUSInE97cnw
JMk3Im3E7wRrQLZhN7VcBOeeWf4EYU+VTZvV06OzZVl7dtrxBjhgdFbN0KD7Xhih
qrJvOvBfj7TshQHh4Dh1KtytX5rvhWGmYHE7ABEBAAH+CQMIXbfc7ql14bpgXPNk
UrxI2U2q6YRaOf7nwE9DmPkDniABA8xF+JhDCPKb4BoHgwO0FQT+oTqpEwniHGyK
q6Wi7E/NuJWNStD3SuTeS13nncpTnkquq2Dw9TXaLPMXKCl0WyY3+yByOw2GolCp
4tcUGUytNPB4mr91JI3GFn/AN97CPjatCKsUxyJHugFsBrp5UZiXZI5DBS3SfpXv
Is3dWmrlOvC/o48K6DdOHFTLaHBTow4veIec2N/K3nD6lapw5+T4vvvUWnFL3333
YPYGqpf/6pCw/0x5NWIL5+mGhVDQrX+UNruUgXs7ZurvExMLsRNxBc03KL9W53Hz
RRqjGpmvaUvpqX3JaKuNJ9cldP9iVgTNF87URfwIPzfb6iCyr6+xD9n/NksgAHjs
rww2gdLadJJ4ObYQ39/DKifIQg3eBtfr35SCk8jN9nchaC6wqJzZZXrcquDtBB4K
F3+pi4D3y++r2WVcxTuY3ExDD9/NCnaistrzcwMo5Rl7LDRzWUI7nZ9ZS5ez6USK
yYhhXVHXJUSACtR5sfMThKjiMxQbZCPT4hL7ZsPLoDDtoaM8LiPZB0BPPVzyTTy4
mrZoNHvvb1WSidKrUnuifje63uTxS6eg4Og6pN/N/ir54Gn4jYe+/kOU392Czpkr
FV/RQdO4jrnEfer0i5OjEPj+aRCqbefn7cYT57Y3kA9njdPDZ9SBJlOlN1yV3S75
sin3DowUUKM/Ze8/0ZkquMVcRe7aMYtj1FutFhSMxv9bAVlf8VLrQtZxHJ2z5yiH
FrNjvX8NGoqdGnKDdPGAriAFnfAPO3RV3DPc7d3hSjoJLkJUyoxIHcm6b3wATG9c
tLgzjqfYbvAVUuBvWdERaX5yaO5u4e4y/pJRLWtLbRei49p5+z5IlUgB/Wkqdtvo
2r53aR4pFzM0zRt0ZXN0ICh0ZXN0KSA8dGVzdEB0ZXN0LmNvbT7CwG0EEwEKABcF
AlvitusCGy8DCwkHAxUKCAIeAQIXgAAKCRBMrSAyOGuFVpD6B/0UK46kTfUxt+gs
LqCMkjL9a0LOnYiDYlPxTUyL92lfSKVYlQVhvsZImDRk1xWWoVqKT3ewrYweIcmT
9cYOfvMuCX5q6yEiZQBos0RU5SrjHPuATP2xLm+Xz4rni6s9NO8Q2NFtOev0I68T
DH4RyTr9VioTpAG5G+r1xShyvNEa071lKLqQEMdSWv8pNLyMPopJDDFr3AaQbgIB
9tmOAM2LMhL/+yMddIKOaEh/waoIgN94wvKFEEE2EIQWqByvIS/Ev1MIGUqS8zg6
+dVlpU/eKYKOKFq8atWY014BpeqtY/h8YkuwuI3VcVlZq8FvkdG8p7hxA8hjJdNP
nnl8H5xHx8MGBFvitusBCAC3lxKY8wG9JM260yIlLC/0tm3MZ+ddbeDQOpl/8URg
z0oXz0oRO/HsuG3qYcSuoPkhcc/KY4vqiWcCuJgiT/2meeII31KW5Bd7sGRY1jME
6WPSGq3Jg3hqhlNaKsE6yGK8reiE5KdvgrpUUMGP8hpGC1tdME9xOxQekjPd++/6
ptNjCSX6V1nvuvDLqG0Dr1a9pm1vuCg7pMtdOAUVwZWq6lA3DR5rshxNyHq80Yx1
8N2rE2NXcYfTx4K9hdMIfIpl5isP0pqufmiYOQ8wwN3iHArLabxlP5rjOeuNhZ9I
tM6/sUCnIFKl+P+9cbNO2SqlAe2E9JMzZBEQ5jM4p6ltABEBAAH+CQMI8IPHqlsr
x35gLUXHJx4OV0d/f5VOTgWsjCz0OIHq2rthZRzCiNqi+mnqP4WKk1CT9CBiJV7G
TMRcD4jHpEvXCHfbnrFJmR5ZzSaY1NbmOywiLFKlw9X+vx+NUCor6cuBzQty4NyS
/9OpW4blRVvh++S814i9fGiVoba//16SnuSORdJoW4PpI9n9oSv0ytP0fhtMmEPr
UtKa54I97LoOb8iNuzTlUZuMndbP8rV2XUHRKZweR9I+XAHWsgzEu3lGxdKxv85P
Jn33g5J091t4VOWn3zl8x3g3E+Vl9eMo+AyTHiYjqvPSR5IdQFVz6/wbiqoBMAkT
+DT1kj9MJh2VAkNEt4pcyVxRPXjasJcvxwBbJD2V0orFpZmYdcA024Y6CWE3KgJ4
iRk784AMrOgnp1h+SushJmGky5Q77SKNLWescZnrpIYNw/4oUSqot2daWJBNsTMT
UtXFYZNpTeVhGL2cJCmrc6GRKpStHRdxCj7FIB38f+zSUpxkCfTHwL+spdEnDaKQ
DkebwLbXf6na9nFkTzs5w90HAKEWF52sMnMU7H56x53edSdoayHgPX4A2O0jrQp4
I4LgEYHJ387EhQp3UmNsg8VyaQQCDYBTCPTN9/0U3st8ggw6zQvWebrKEoRVcy3e
9slnCe93uIzxdPXtnsiPUvmhUtBmQ5mqLVxwk02Xed+kNPpCcMdeWuSD5q6E+Xhr
4s75doHuhyHGE5FCb2wE5VCeHfUzXpbKHA5PQR58YCODiE/ElrMcL512mOxA1Pmb
SGHhnHS11VGsKPz92NTy6+IvcB2TdOw7aN3lvXRoLo5PM1aYGvxeOf6nUebBTff5
2Dvo21OhkUadUrwxQfERVaEvvalSxdicLuDpH7FGYjPKeFyuIkkyT/hNKFWrcx3a
7d64gSRK7ducC3h5yMh3wsGEBBgBCgAPBQJb4rbrBQkPCZwAAhsuASkJEEytIDI4
a4VWwF0gBBkBCgAGBQJb4rbrAAoJEB8Cpv8Djx3MNiYIALDj2nCYi77Tpaxz/TMO
XdctYR700PBBx1U4ojGCGNDn7ewfFXtOGwdt5Y8ZJBeTO8ioQOp3pdgSlxo6t3Bm
umHamjzx6Z781Xs/uCKj+BELRYUT9ulr+SjQRO91H6OFG8wzknQf/ZxEpXWrOC+L
UmwagjPjtJyaTw25AcQrhhqfQ+3x2eUYFab5L2dDfnQmAj86Io+ADXOqLjwoTYat
/pKHHtcn9Eyys24b5CA9jUiWk9BIEaz6wbYKj5hC2mTvdBUFCXlnFiywReacOxwN
NkB3r5h8A/njYhUWpibLdNf+J7+byB8jTBy/PvxFtx/sgkhlLQFmKx/Do2qWl8je
QHcDoggA8d6JhqCAhzE1O6prwDERUI2mtoGH3fD0r+uOEqCTfPu9WtvmgxM5mREz
jlroi0bqdRMEORRfiUNXqsKLFE02+od2UzV9DinEJi1JHjFnOFaudVRryZdvgcKG
pQV36I3OdS4Kc/G9ki3bR3Vybmzi0rdwq2n4b1o5tl1SVz6JRj9T+1Zy8xJB9ATy
C4PrJfcC2g/HR/CTAjLgydQP+mq2ZyN1Kxrg+3Td3mRHZkH8UT+TKV+wHjwf5IhQ
hK4WcMzjgTBWaG64+EhG4S9K2o+D3LfkWO64+vArHvAdHvep7xfi8R7NNz90Drp/
Sd/MpBEiZs//AakJV68Ly7/bGXc3CMfDBgRb4rbrAQgAwn7nlPQBTxejrw75SNLJ
iaHFl8FdD7Qu7/n2taAinBK2fERJ0itO1QdLx6rsOXg2yGQYFy0SjL6tYK7jtKtN
/k8dKA4VnFuyX5WHxOb0CZsnai9o6qlGzYPxWnAfdl7nQYbabH9B7hrnKIWFI9Qg
PeocTPgX58OjaSfBmmQ3ZQpISSVN4kSdJvm0HqnTZ66UpeqGbD8rdCJ1wZFQeSxU
nrIq8HQJT92wZX5/9WVIxiEz2EqwNBDwiy4cHVnrHwoAHNfl7D3smfuu1w6D5WOd
0OCt+uqpPoEJR8ZkB7Szps8Olyons/p+eGK5cZ9DRGyjHY2SjfTKNi4UnUEQ5ye7
xwARAQAB/gkDCIYyVOwg51KiYD7pVb5/y6uItwv9SXDVGUoSbidUh+tCAXwmMR7p
kWyqTF+dUUBvdTpS9OgZCI7DWohcNTDANBfym4lCSkY62NeYcDkoDGDVdfZ9dzwm
vOvNqTfyEI9vLCWJREkQ2DeaOehsl+N6a1pXiH2QnsyaIZ1iHPm0sijknJJbUJXe
XpBcbxghUMmYqPzssGNSAT8exC35QFb4RKI4J4/3A9v1W6VfPGoiHhmf1n9MJXyC
KesYH9ukTwM4eOpJknWGMDvcbwr+64URdXmD9x4yeuq5c8UiMWHNwk8evocchB0x
jg/AXZhPfUlXvUYCXqPnede9DztgTVfIyryNd/9mNbS8JX9MTAqdCPYrbF1RZEA6
SsbLCS88lzTy9Pb1/B0EiUgBqILDgsLVTElGp6TTxPUVVpE/FBNk8BWT5Z1aEP/y
cR9Uh2dNKFJXIjanb+6QiLLN0rQfpWpDrNzQT9UNcG8ckC985pfMy+wKIBgHq9+x
WJ3ggc4pi16bzn9RyAQwqDJ8d/yncjBVTE7ZZStKY13Oh6lNdMPR2lJgsDaw+hGG
PjztNGH0oBqidgvAxYfSiMnTRuVScvSiXOI/l/u9g58ka0D+NnQ2UBGsU8Woijs7
rG9uOQu+vZe3f+8ugIIMigLlqdzKQAKLtBYlrOZ5MHFY9QHtd5LAlRcm/PiBXA1c
gS6zeNo1MjVuM7tKJDj+EsFrunKQ0KpUoddFidScqRO/4m3J5tyUCEZK/CAoq8ht
1KTXWch/41vKMkG/242V0TYcn8r1AR1as2HM1FhSCOxWQFhetfq0I3/dh6D44qns
k2CWZF0yJ4FmEnmT44woRastZ1+1sTAWM7k7TkKMwyLfGO+vrXjv/BBBkMXA8UgE
h0NJBIBARIIUUseTAterl5fW0lsxbWsWuU1RiJmXK8LBhAQYAQoADwUCW+K26wUJ
DwmcAAIbLgEpCRBMrSAyOGuFVsBdIAQZAQoABgUCW+K26wAKCRCEsTLdxLXGiWwr
B/9xDgfo4sGrQSDhtyCaLmY6h8YRC3tWmJINj71rUl1RAJiY3k0BzGVo2TSvtMpc
kstaKtQBB7B1/LMGhyUl0zxE1nNET4/MpXhe33xLj4QoMy+jlHoChWM3Z8UQdvJx
YMTl45hZSLO/IqvyFQCIaG3psk8aw8yGZMiq0BPCdcHf4jeMGCEblP4MNIM00vVp
0FzrDMoK45m5RrVyXMFKoQdOrjM+Nccko2pgIIkERP/ad47GBz4yJty00aqpp1QK
lSyPGmSbPS6ZsH7dySPViJRW2A9AHh7oj9xsQ9x9bHyzRqQ8YrTFkW98YX81BZ1n
rwe7qbAY3FtM8bo5uTmBvRl64R0H/1KOZvyroCcrbknK4e/+YJWIBDA3p6TC9WzZ
dGempiJSUskL+oS4gXCA/5ZGqQ7xjNLC7dNKWnJtQxuak4eNC+5hxZ4MGQv339Lv
t4V1BjKBsZ18mrwwACfB124/zNmRnFjxvxARsVTocGNy3rPCBk4Qi1/y/g/QxR3B
Rj0qaKkbCcE0N2aZDOj6hLvEgzgjmspTE6Jpq8D7jnAEnlhgcYIF4+ktjYEExDHL
YSVuiRbqqjI/ryttaxwBDkysAuEnVVgOYS9xVIWpc3KiLO9ibk6r15kOiiUE7u81
BxaVhngI9MFLA4VdahGkUAUcpWi9NEHYLBPlPX4mKAdtRLxD1no=
=DOtl
-----END PGP PRIVATE KEY BLOCK-----`

func TestPrivateKeyEncryption(t *testing.T) {

	p, err := Create("test", "test@test.com", 1024, 0)
	if err != nil {
		t.Fatal("Couldn't create new PGP Keys", err)
	}

	privateKey := p["private"]

	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(privateKey))
	if err != nil {
		t.Fatal("Couldn't read PrivateKey", err)
	}
	entity := entitylist[0]

	beforeEncryption := entity.PrivateKey.PrivateKey.(*rsa.PrivateKey)
	rsaN := beforeEncryption.N
	rsaE := beforeEncryption.E
	rsaD := beforeEncryption.D
	rsaP0 := beforeEncryption.Primes[0]
	rsaP1 := beforeEncryption.Primes[1]
	rsaQinv := beforeEncryption.Precomputed.Qinv

	passphrase := "This is a Test Passphrase!"
	encryptedBytes, err := EncryptPrivateKeys(passphrase, privateKey)
	if err != nil {
		t.Fatal("Couldn't encrypt PrivateKey", err)
	}

	newEntitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(encryptedBytes))
	if err != nil {
		t.Fatal("Couldn't read encrypted PrivateKey", err)
	}
	newEntity := newEntitylist[0]

	newEntity.PrivateKey.Decrypt([]byte(passphrase))
	if err != nil {
		t.Fatal("Couldn't decrypt PrivateKey", err)
	}

	afterEncryption := newEntity.PrivateKey.PrivateKey.(*rsa.PrivateKey)
	rsaNrestored := afterEncryption.N
	rsaErestored := afterEncryption.E
	rsaDrestored := afterEncryption.D
	rsaP0restored := afterEncryption.Primes[0]
	rsaP1restored := afterEncryption.Primes[1]
	rsaQinvrestored := afterEncryption.Precomputed.Qinv

	if rsaN.Uint64() != rsaNrestored.Uint64() {
		t.Fatal("N parameter mismatch:", rsaN, rsaNrestored)
	}
	if rsaE != rsaErestored {
		t.Fatal("E parameter mismatch:", rsaE, rsaErestored)
	}
	if rsaD.Uint64() != rsaDrestored.Uint64() {
		t.Fatal("D parameter mismatch:", rsaD, rsaDrestored)
	}
	if rsaP0.Uint64() != rsaP0restored.Uint64() {
		t.Fatal("Prime 0 parameter mismatch:", rsaP0, rsaP0restored)
	}
	if rsaP1.Uint64() != rsaP1restored.Uint64() {
		t.Fatal("Prime 1 parameter mismatch:", rsaP1, rsaP1restored)
	}
	if rsaQinv.Uint64() != rsaQinvrestored.Uint64() {
		t.Fatal("Qinv parameter mismatch:", rsaQinv, rsaQinvrestored)
	}

	afterEncryption.Validate()
	if err != nil {
		t.Fatal("PrivateKey validation failed: ", err)
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
var invalidPublic = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xn0EW3/XKQEDgLVGyA9YFjuvlD2eUAeLFp6oE8VWcUssfenoeRebVVH3XQD2+/wM
Ws2ht1qN96jPX7rZIG84/2zP8/kHmUtmWRPFKdBong4rmpSbZmGiXi1+WePY1lwE
/vbZzuOTcrJmnKDme7XXBxwpJNKTl7PXqh8AEQEAAc0AwqoEEwEIAC4FAlt/1ykJ
EDRTkesK7wPNAhsDBQkAAAACAhkBBgsJCAcDAgYVCAIJCgsDFgIBAADtnAOAfqRd
a2UgiKVupj/oX1S7TnUq3bSucuJOo+erGr7v6cbmEu5xtGSwcQiZIoZIzQs+WKWE
UXpEWgbir9Eh6NuJfgh0DSI3GhiSnUu4eEU7Ae9Rf8+eRaYGaMr0j8vRTIVUdgy9
ua8RweOYKo4pO0LVAqz+ck87RKDoF4FJvluxqK6+quN5Mr5ZZXX1ABEBAAHClQQY
AQgAGQUCW3/XKQkQNFOR6wrvA80CGwwFCQAAAAIAAK0AA4BbnXYbGDCCMYK1hmsW
yKgpOpwX+cIdHBx/JuaY/pLtx8YFWyF1TWZycwUAdvinQgNVvz7CNpxl9vpZIgJM
psy5CI11xWth8FP5OFx3qIU1WB+FUuFMkaA7rNNMcO/k2DamYr/eG4zObs/viZbY
+fh0
=9S0f
-----END PGP PUBLIC KEY BLOCK-----`

var invalidPrivate = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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

func TestExpiry(t *testing.T) {
	//keyPair, err := Create("", "", 896, 2 * time.Second)
	keyPair := map[string][]byte{"public": []byte(expiredPublic), "private": []byte(expiredPrivate)}
	s := []byte("encrypt already!")
	myBytes, err := Encrypt(s, [][]byte{keyPair["public"]})
	if err == nil {
		t.Error("Ecryption error: ", err)
	}
	//fmt.Println("encrypted: ", string(myBytes))
	myBytes, err = Decrypt(myBytes, nil, keyPair["private"])
	if err == nil {
		t.Error("decrypt error : ", err)
	}
	if bytes.Equal(myBytes, s) {
		t.Error("Decrypting finished with error: ", myBytes)
	}
}

func TestReadIdentity(t *testing.T) {
	myBytes, err := ReadIdentity([][]byte{[]byte(_publicKey), []byte(_pubKey2), []byte(_pubKey3)})
	if err != nil {
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
	if err != nil {
		t.Error("Signing error: ", err)
	}
	valid, err := Verify(data, []byte(myBytes), [][]byte{[]byte(sigPub)})
	if err != nil || !valid {
		t.Error("Verify error: ", err)
	}
}

func TestVerify(t *testing.T) {
	valid, err := Verify([]byte("abc"), []byte(sigMsg2), [][]byte{[]byte(sigPub)})
	if err != nil || !valid {
		t.Error("Verify error: ", err)
	}
	valid, err = VerifyBundle([]byte(sigMsg), [][]byte{[]byte(sigPub)})
	if err != nil || !valid {
		t.Error("Verify error: ", err)
	}
}

const _mySignature = `
-----BEGIN PGP SIGNATURE-----

wqUEAAEIABAFAljclusJECgqilxK/fP0AAB9uwRIcSbgzJOalzbUOjcYzIEqR9zX
y3Z8JTCbWk1YdTKhkrLD7sYhACQ4FIYNTuE1Aq52IuL4MuFnWCpLsIi3PYql7cL1
BOkuhlxt9gQunTSfaluo62WS51p74wnBoSXVzICNKu64mugkGzgaUSJpwNYrBnLC
sQDy4JdFtg4kZ+1GIA2K6laj1H0iFsQ=
=onAz
-----END PGP SIGNATURE-----`

func TestEncrypt(t *testing.T) {
	myBytes, err := Encrypt([]byte("omfg encrypt already!"), [][]byte{[]byte(_publicKey), []byte(_pubKey2), []byte(_pubKey3)})
	if err != nil {
		t.Error("Ecryption error: ", err)
	}
	myBytes, err = Decrypt(myBytes, []byte("abc"), []byte(privateKey1))
	if err != nil {
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
const _pubKey2 = `
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
const _pubKey3 = `
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
	if err != nil {
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

func TestReadPublicKey(t *testing.T) {
	a, err := ReadPublicKey([]byte("abc"), []byte(sigPriv))
	if err != nil {
		t.Error("Reading public key failed !!!", err)
	}
	if bytes.Compare(a, []byte(sigPub)) != 0 {
		t.Error("Reading public key failed !!!", err)
	}
}

func TestWriteIdentity(t *testing.T) {
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

var privateKey1 string = `-----BEGIN PGP PRIVATE KEY BLOCK-----
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
