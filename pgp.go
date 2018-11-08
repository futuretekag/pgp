package pgp

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/elgamal"
	openpgperrors "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

const (
	md5       = 1
	sha1      = 2
	ripemd160 = 3
	sha256    = 8
	sha384    = 9
	sha512    = 10
	sha224    = 11
)

func Create(name, email string, rsaBits int, expiry time.Duration) (map[string][]byte, error) {
	// Create the key
	if rsaBits < 10 {
		rsaBits = 1096
	}
	cfg := &packet.Config{RSABits: rsaBits}
	key, err := openpgp.NewEntity(name, "", email, cfg)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	// Set expiry and algorithms. Self-sign the identity.
	dur := uint32(expiry.Seconds())
	for _, id := range key.Identities {
		id.SelfSignature.KeyLifetimeSecs = &dur

		id.SelfSignature.PreferredSymmetric = []uint8{
			uint8(packet.CipherAES256),
			uint8(packet.CipherAES192),
			uint8(packet.CipherAES128),
			uint8(packet.CipherCAST5),
			uint8(packet.Cipher3DES),
		}
		id.SelfSignature.PreferredHash = []uint8{
			sha256,
			sha1,
			sha384,
			sha512,
			sha224,
		}

		id.SelfSignature.PreferredCompression = []uint8{
			uint8(packet.CompressionZLIB),
			uint8(packet.CompressionZIP),
		}
		err := id.SelfSignature.SignUserId(id.UserId.Id, key.PrimaryKey, key.PrivateKey, cfg)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}

	// Self-sign the Subkeys
	for _, subkey := range key.Subkeys {
		subkey.Sig.KeyLifetimeSecs = &dur
		err := subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, cfg)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}

	buf := new(bytes.Buffer)
	ar, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	key.Serialize(ar)
	ar.Close()

	public := buf.Bytes()

	buf = new(bytes.Buffer)
	ar, err = armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	key.SerializePrivate(ar, nil)
	ar.Close()

	private := buf.Bytes()
	return map[string][]byte{"public": public, "private": private}, nil
}

func ValidatePublicKey(publicKey []byte) bool {
	_, err := ReadIdentity([][]byte{publicKey})
	if err != nil {
		return false
	}
	return true
}

func ValidatePrivateKey(privateKey []byte) bool {
	_, err := ReadIdentity([][]byte{privateKey})
	if err != nil {
		return false
	}
	return true
}

func Sign(msg []byte, passphrase []byte, privKey [][]byte) ([]byte, error) {
	input := new(bytes.Buffer)
	input.Write(msg)
	output := new(bytes.Buffer)
	err := SignStream(input, output, passphrase, privKey)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func SignStream(in io.Reader, out io.Writer, passphrase []byte, privKey [][]byte) error {
	entitylist, err := readKeys(privKey)
	if err != nil {
		return err
	}
	// Decrypt private key using passphrase
	for _, entity := range entitylist {
		if entity.PrivateKey == nil {
			return os.ErrInvalid
		}
		if err = decryptPrvIfNecessary(passphrase, entity.PrivateKey); err != nil {
			return err
		}
		for _, subkey := range entity.Subkeys {
			if err = decryptPrvIfNecessary(passphrase, subkey.PrivateKey); err != nil {
				return err
			}
		}
	}

	err = openpgp.ArmoredDetachSignText(out, entitylist[0], in, nil)
	if err != nil {
		return err
	}
	return nil
}

var sigWithDataReg = regexp.MustCompile(`-----BEGIN.*\nHash:.*\n\n(.*)\n(-----BEGIN[\s\S]+)`)

func VerifyBundle(signatureIncludingData []byte, pubkey [][]byte) (bool, error) {
	regexRes := sigWithDataReg.FindAllSubmatch(signatureIncludingData, 1)
	if len(regexRes) == 1 && len(regexRes[0]) == 3 {
		return Verify(regexRes[0][1], regexRes[0][2], pubkey)
	}
	return false, errors.New("couldn't parse the signed data of your input!")
}

func Verify(data, signature []byte, pubKey [][]byte) (bool, error) {
	return VerifyStream(bytes.NewBuffer(data), bytes.NewBuffer(signature), pubKey)
}

func VerifyStream(dataReader, signatureReader io.Reader, pubKey [][]byte) (bool, error) {
	entitylist, err := readKeys(pubKey)
	if err != nil {
		return false, err
	}

	block, err := armor.Decode(signatureReader)

	if block.Type != openpgp.SignatureType {
		return false, errors.New("Invalid signature")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return false, err
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return false, errors.New("Invalid signature")
	}
	hash := sig.Hash.New()
	_, err = io.Copy(hash, dataReader)
	if err != nil {
		return false, err
	}
	err = entitylist[0].PrimaryKey.VerifySignature(hash, sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func Encrypt(msg []byte, pubKey [][]byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(msg)
	armored := new(bytes.Buffer)
	_, err := EncryptStream(buf, armored, pubKey)
	if err != nil {
		return nil, err
	}
	return armored.Bytes(), nil
}

func EncryptStream(in io.Reader, out io.Writer, pubKey [][]byte) (int64, error) {
	entitylist, err := readKeys(pubKey)
	if err != nil {
		return 0, err
	}
	armWr, err := armor.Encode(out, "PGP MESSAGE", make(map[string]string))
	if err != nil {
		return 0, err
	}
	w1, err := openpgp.Encrypt(armWr, entitylist, nil, nil, nil)
	if err != nil {
		return 0, err
	}
	var n int64
	n, err = io.Copy(w1, in)
	if err != nil {
		return n, err
	}
	err = w1.Close()
	if err != nil {
		return n, err
	}
	err = armWr.Close()
	if err != nil {
		return n, err
	}
	return n, nil
}

func Decrypt(msg, passphrase, privKey []byte) ([]byte, error) {
	decbuf := bytes.NewBuffer(msg)
	out := new(bytes.Buffer)
	_, err := DecryptStream(decbuf, out, passphrase, privKey)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func DecryptStream(in io.Reader, out io.Writer, passphrase, privKey []byte) (int64, error) {
	var n int64
	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(privKey))
	if err != nil {
		return 0, err
	}
	entity := entitylist[0]
	if err = decryptPrvIfNecessary(passphrase, entity.PrivateKey); err != nil {
		return 0, err
	}

	for _, subkey := range entity.Subkeys {
		if err = decryptPrvIfNecessary(passphrase, subkey.PrivateKey); err != nil {
			return 0, err
		}
	}

	// Decrypt armor encrypted message using decrypted private key
	result, err := armor.Decode(in)
	if err != nil {
		return 0, err
	}

	md, err := openpgp.ReadMessage(result.Body, entitylist, nil /* no prompt */, nil)
	if err != nil {
		return 0, err
	}
	n, err = io.Copy(out, md.UnverifiedBody)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func decryptPrvIfNecessary(passphrase []byte, priv *packet.PrivateKey) error {
	if passphrase != nil && priv != nil && priv.Encrypted {
		err := priv.Decrypt(passphrase)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadPublicKey(passphrase, privKey []byte) ([]byte, error) {
	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(privKey))
	if err != nil {
		return nil, err
	}
	entity := entitylist[0]
	wrf := func(key *openpgp.Entity) []byte {
		buf := new(bytes.Buffer)
		ar, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		key.Serialize(ar)
		ar.Close()
		return buf.Bytes()
	}
	// Decrypt private key using passphrase
	if entity.PrivateKey != nil {
		if err = decryptPrvIfNecessary(passphrase, entity.PrivateKey); err != nil {
			return nil, err
		}
		for _, subkey := range entity.Subkeys {
			if err = decryptPrvIfNecessary(passphrase, subkey.PrivateKey); err != nil {
				return nil, err
			}
		}
		return wrf(entity), nil
	}
	return nil, os.ErrNotExist
}

func ReadIdentity(pubKey [][]byte) ([]map[string]string, error) {
	entitylist, err := readKeys(pubKey)
	if err != nil {
		return nil, err
	}
	var re = regexp.MustCompile(`(.*?) <(.*?)>`)
	var resultArray = make([]map[string]string, len(entitylist), len(entitylist))
	for i, e := range entitylist {
		for mk := range e.Identities {
			for _, match := range re.FindAllStringSubmatch(mk, -1) {
				resultArray[i] = make(map[string]string, 2)
				resultArray[i]["name"] = match[1]
				resultArray[i]["email"] = match[2]
			}
		}
	}
	return resultArray, nil
}

func WriteIdentity(pw, privKey []byte, name, comment, email string) (map[string][]byte, error) {
	entitylist, err := readKeys([][]byte{privKey})
	if err != nil {
		return nil, err
	}
	wrf := func(key *openpgp.Entity) []byte {
		buf := new(bytes.Buffer)
		ar, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		key.Serialize(ar)
		ar.Close()
		return buf.Bytes()
	}
	wrff := func(key *openpgp.Entity) []byte {
		buf := new(bytes.Buffer)
		ar, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		serializePrivateWithoutResigning(key, ar, nil)
		ar.Close()
		return buf.Bytes()
	}
	res := map[string][]byte{}
	for _, e := range entitylist {
		if e.PrivateKey != nil {
			if err = decryptPrvIfNecessary(pw, e.PrivateKey); err != nil {
				return nil, err
			}
			for _, subkey := range e.Subkeys {
				if err = decryptPrvIfNecessary(pw, subkey.PrivateKey); err != nil {
					return nil, err
				}
			}
		} else {
			return nil, os.ErrInvalid
		}
	}
	for _, e := range entitylist {
		for _, ii := range e.Identities {
			ii.UserId.Name = name
			ii.UserId.Comment = comment
			ii.UserId.Email = email
			if comment != "" {
				comment += " "
			}
			ii.UserId.Id = fmt.Sprintf("%s %s<%s>", name, comment, email)
			err = ii.SelfSignature.SignUserId(ii.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
			if err != nil {
				return nil, err
			}
		}
	}
	if len(entitylist) == 1 {
		res["public"] = wrf(entitylist[0])
		res["private"] = wrff(entitylist[0])
		return res, nil
	}

	return nil, errors.New("not implemented")
}

// SerializePrivate from openpgp but without SubKey re-signing to retain valid signing subkey cross-certification signature
func serializePrivateWithoutResigning(e *openpgp.Entity, w io.Writer, config *packet.Config) (err error) {
	err = e.PrivateKey.Serialize(w)
	if err != nil {
		return
	}
	for _, ident := range e.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return
		}
		err = ident.SelfSignature.SignUserId(ident.UserId.Id, e.PrimaryKey, e.PrivateKey, config)
		if err != nil {
			return
		}
		err = ident.SelfSignature.Serialize(w)
		if err != nil {
			return
		}
	}
	for _, subkey := range e.Subkeys {
		err = subkey.PrivateKey.Serialize(w)
		if err != nil {
			return
		}
		//Removed to avoid overwriting exsting valid Sig and Embedded Sigs
		//err = subkey.Sig.SignKey(subkey.PublicKey, e.PrivateKey, config)
		//if err != nil {
		//	return
		//}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return
		}
	}
	return nil
}

func EncryptPrivateKeys(passphrase string, privateKey []byte) ([]byte, error) {
	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(privateKey))
	if err != nil {
		return nil, err
	}
	entity := entitylist[0]

	if entity.PrivateKey.Encrypted {
		return privateKey, nil
	}

	buf := new(bytes.Buffer)
	ar, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}

	encryptPriv := func(p *packet.PrivateKey, w *io.WriteCloser) (err error) {
		privencryption := new(EncryptablePrivateKey)
		privencryption.NewEncryptablePrivateKey(p)
		err = privencryption.Encrypt([]byte(passphrase))
		if err != nil {
			return err
		}
		err = privencryption.SerializePrivate(*w)
		if err != nil {
			return err
		}
		return nil
	}

	err = encryptPriv(entity.PrivateKey, &ar)
	if err != nil {
		return nil, err
	}

	for _, ident := range entity.Identities {
		err = ident.UserId.Serialize(ar)
		if err != nil {
			return nil, err
		}
		err = ident.SelfSignature.SignUserId(ident.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil)
		if err != nil {
			return nil, err
		}
		err = ident.SelfSignature.Serialize(ar)
		if err != nil {
			return nil, err
		}
	}

	for _, subkey := range entity.Subkeys {
		err = encryptPriv(subkey.PrivateKey, &ar)
		if err != nil {
			return nil, err
		}
		//Removed to avoid overwriting exsting valid Sig and Embedded Sigs
		//err = subkey.Sig.SignKey(subkey.PublicKey, entity.PrivateKey, nil)
		//if err != nil {
		//	return nil, err
		//}
		err = subkey.Sig.Serialize(ar)
		if err != nil {
			return nil, err
		}
	}
	ar.Close()
	return buf.Bytes(), nil
}

func readKeys(keys [][]byte) (el openpgp.EntityList, err error) {
	for _, key := range keys {
		entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(key))
		if err != nil {
			return nil, err
		}
		for _, e := range entitylist {
			el = append(el, e)
		}
	}
	return el, nil
}

/*
  EncryptablePrivateKey provides
    func (pk *EncryptablePrivateKey) NewEncryptablePrivateKey(priv *packet.PrivateKey)
    func (pk *EncryptablePrivateKey) Encrypt(passphrase []byte) error
    func (pk *EncryptablePrivateKey) SerializePrivate(w io.Writer) error

*/

type EncryptablePrivateKey struct {
	packet.PrivateKey

	//privatekey encryption variables
	encryptedData []byte
	cipher        packet.CipherFunction
	s2k           func(out, in []byte)
	sha1Checksum  bool
	iv            []byte

	//encryption key derivation variables
	s2kmode  uint8       // only inverted+salted mode is used
	s2khash  crypto.Hash // Crypto.SHA256 is used
	s2kckc   uint8       // only sha1 checksum is used
	s2ksalt  []byte      // randomly generated
	s2kcount uint8       // as per s2kcountstd constant
}

//s2kmode constants
const (
	s2ksimple         uint8 = 0
	s2iterated        uint8 = 1
	s2kiteratedsalted uint8 = 3 // only inverted+salted mode is used
)

//s2kckc constants
const (
	s2knon      uint8 = 0
	s2ksha1     uint8 = 254 // only sha1 checksum is used
	s2kchecksum uint8 = 255
)

const (
	packetTypePrivateKey    uint8 = 5
	packetTypePublicKey     uint8 = 6
	packetTypePrivateSubkey uint8 = 7
)

const s2kcountstd uint32 = 65011712 // s2k iterations used
const s2kcountstd_octet uint8 = 255 // s2k iterations used

func (pk *EncryptablePrivateKey) NewEncryptablePrivateKey(priv *packet.PrivateKey) {
	pk.PrivateKey = *priv
}

//Encrypts private key with aes-128 CFB, based on an iterated/salted s2k key derivation
//of the supplied passphrase and uses SHA1 as checksum
func (pk *EncryptablePrivateKey) Encrypt(passphrase []byte) error {
	switch pk.PrivateKey.PrivateKey.(type) {
	case *rsa.PrivateKey, *dsa.PrivateKey, *ecdsa.PrivateKey, *elgamal.PrivateKey:
		privateKeyBuf := bytes.NewBuffer(nil)
		err := pk.serializePrivMPI(privateKeyBuf)
		if err != nil {
			return err
		}
		privateKeyBytes := privateKeyBuf.Bytes()

		//key derivation
		key := make([]byte, 16)
		pk.s2ksalt = make([]byte, 8)
		rand.Read(pk.s2ksalt)
		pk.s2k = func(out, in []byte) {
			s2k.Iterated(out, pk.s2khash.New(), in, pk.s2ksalt, int(s2kcountstd))
		}
		pk.s2khash = crypto.SHA256
		pk.s2k(key, passphrase)
		pk.s2kmode = s2kiteratedsalted
		pk.s2kcount = s2kcountstd_octet

		//encryption
		block, _ := aes.NewCipher(key)
		pk.iv = make([]byte, block.BlockSize())
		rand.Read(pk.iv)
		cfb := cipher.NewCFBEncrypter(block, pk.iv)
		h := crypto.SHA1.New()
		h.Write(privateKeyBytes)
		sum := h.Sum(nil)
		privateKeyBytes = append(privateKeyBytes, sum...)
		pk.s2kckc = s2ksha1

		pk.encryptedData = make([]byte, len(privateKeyBytes))

		cfb.XORKeyStream(pk.encryptedData, privateKeyBytes)
		pk.Encrypted = true

		return err
	}
	return openpgperrors.UnsupportedError("no exportable private key found")
}

func (pk *EncryptablePrivateKey) SerializePrivate(w io.Writer) error {
	buf := bytes.NewBuffer(nil)

	if pk.Encrypted {
		pk.serializeSecretKeyPacket(buf)
	} else {
		return openpgperrors.UnsupportedError("only encrypted private keys supported")
	}

	ptype := packetTypePrivateKey
	contents := buf.Bytes()
	if pk.PrivateKey.PublicKey.IsSubkey {
		ptype = packetTypePrivateSubkey
	}
	err := serializeHeader(w, ptype, len(contents))
	if err != nil {
		return err
	}
	_, err = w.Write(contents)
	if err != nil {
		return err
	}
	return nil
}

func (pk *EncryptablePrivateKey) serializeSecretKeyPacket(w io.Writer) error {
	err := serializePublicKey(&pk.PrivateKey.PublicKey, w)
	if err != nil {
		return err
	}

	privateKeyBuf := bytes.NewBuffer(nil)
	encodedKeyBuf := bytes.NewBuffer(nil)

	//checksum sha1
	encodedKeyBuf.Write([]byte{uint8(pk.s2kckc)})

	//cipher aes-128
	pk.cipher = packet.CipherAES128
	encodedKeyBuf.Write([]byte{uint8(pk.cipher)})

	//s2k iterated/salted
	encodedKeyBuf.Write([]byte{pk.s2kmode})
	hashID, ok := s2k.HashToHashId(pk.s2khash)
	if !ok {
		return openpgperrors.UnsupportedError("no such hash")
	}
	encodedKeyBuf.Write([]byte{hashID})

	//s2k salt
	encodedKeyBuf.Write(pk.s2ksalt)

	//s2k iterations
	encodedKeyBuf.Write([]byte{pk.s2kcount})

	//encrypted privatekey MPIs
	privateKeyBuf.Write(pk.encryptedData)

	encodedKey := encodedKeyBuf.Bytes()
	privateKeyBytes := privateKeyBuf.Bytes()

	w.Write(encodedKey)
	w.Write(pk.iv)
	w.Write(privateKeyBytes)

	//sha1 hash checksum
	h := crypto.SHA1.New()
	h.Write(privateKeyBytes)
	sum := h.Sum(nil)
	privateKeyBytes = append(privateKeyBytes, sum...)

	return nil
}

func (pk *EncryptablePrivateKey) serializePrivMPI(w io.Writer) error {
	switch pk.PrivateKey.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		rsaPrivateKey := pk.PrivateKey.PrivateKey.(*rsa.PrivateKey)
		return writeMPIs(w, fromBig(rsaPrivateKey.D), fromBig(rsaPrivateKey.Primes[0]),
			fromBig(rsaPrivateKey.Primes[1]), fromBig(rsaPrivateKey.Precomputed.Qinv))
	case packet.PubKeyAlgoDSA:
		dsaPrivateKey := pk.PrivateKey.PrivateKey.(*dsa.PrivateKey)
		return writeMPIs(w, fromBig(dsaPrivateKey.X))
	case packet.PubKeyAlgoElGamal:
		elgamalPrivateKey := pk.PrivateKey.PrivateKey.(*elgamal.PrivateKey)
		return writeMPIs(w, fromBig(elgamalPrivateKey.X))
	case packet.PubKeyAlgoECDSA:
		ecdsaPrivateKey := pk.PrivateKey.PrivateKey.(*ecdsa.PrivateKey)
		return writeMPIs(w, fromBig(ecdsaPrivateKey.D))
	}
	return openpgperrors.InvalidArgumentError("unknown private key type")
}

//exact copy from crypto/openpgp/packet/Packet.go
func serializeHeader(w io.Writer, ptype uint8, length int) (err error) {
	var buf [6]byte
	var n int

	buf[0] = 0x80 | 0x40 | byte(ptype)
	if length < 192 {
		buf[1] = byte(length)
		n = 2
	} else if length < 8384 {
		length -= 192
		buf[1] = 192 + byte(length>>8)
		buf[2] = byte(length)
		n = 3
	} else {
		buf[1] = 255
		buf[2] = byte(length >> 24)
		buf[3] = byte(length >> 16)
		buf[4] = byte(length >> 8)
		buf[5] = byte(length)
		n = 6
	}

	_, err = w.Write(buf[:n])
	return
}

//copy from crypto/openpgp/packet/public_key.go with minimal changes to access publickey data
func serializePublicKey(pk *packet.PublicKey, w io.Writer) (err error) {
	var buf [6]byte
	buf[0] = 4
	t := uint32(pk.CreationTime.Unix())
	buf[1] = byte(t >> 24)
	buf[2] = byte(t >> 16)
	buf[3] = byte(t >> 8)
	buf[4] = byte(t)
	buf[5] = byte(pk.PubKeyAlgo)

	_, err = w.Write(buf[:])
	if err != nil {
		return
	}

	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		rsaPublicKey := pk.PublicKey.(*rsa.PublicKey)
		return writeMPIs(w, fromBig(rsaPublicKey.N), fromBig(big.NewInt(int64(rsaPublicKey.E))))
	case packet.PubKeyAlgoDSA:
		dsaPublicKey := pk.PublicKey.(*dsa.PublicKey)
		return writeMPIs(w, fromBig(dsaPublicKey.P), fromBig(dsaPublicKey.Q),
			fromBig(dsaPublicKey.G), fromBig(dsaPublicKey.Y))
	case packet.PubKeyAlgoElGamal:
		elgamalPublicKey := pk.PublicKey.(*elgamal.PublicKey)
		return writeMPIs(w, fromBig(elgamalPublicKey.P), fromBig(elgamalPublicKey.G),
			fromBig(elgamalPublicKey.Y))
	}
	return openpgperrors.InvalidArgumentError("bad public-key algorithm")
}

//exact copy from crypto/openpgp/packet/public_key.go
type parsedMPI struct {
	bytes     []byte
	bitLength uint16
}

//exact copy from crypto/openpgp/packet/public_key.go
func fromBig(n *big.Int) parsedMPI {
	return parsedMPI{
		bytes:     n.Bytes(),
		bitLength: uint16(n.BitLen()),
	}
}

//exact copy from crypto/openpgp/packet/public_key.go
func writeMPIs(w io.Writer, mpis ...parsedMPI) (err error) {
	for _, mpi := range mpis {
		err = writeMPI(w, mpi.bitLength, mpi.bytes)
		if err != nil {
			return
		}
	}
	return
}

//exact copy from crypto/openpgp/packet/packet.go
func writeMPI(w io.Writer, bitLength uint16, mpiBytes []byte) (err error) {
	// Note that we can produce leading zeroes, in violation of RFC 4880 3.2.
	// Implementations seem to be tolerant of them, and stripping them would
	// make it complex to guarantee matching re-serialization.
	_, err = w.Write([]byte{byte(bitLength >> 8), byte(bitLength)})
	if err == nil {
		_, err = w.Write(mpiBytes)
	}
	return
}
