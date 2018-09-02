package pgp

import (
	"bytes"
	"fmt"
	"errors"
	"regexp"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"time"
	"io"
	"os"
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

func Create(name, email string, rsaBits int, expiry time.Duration) (map[string][]byte, error){
	// Create the key
	if rsaBits < 10{
		rsaBits = 1096
	}
	cfg := &packet.Config{RSABits:rsaBits}
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
	return map[string][]byte{"public":public, "private":private}, nil
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

func Sign(msg []byte, passphrase []byte, privKey [][]byte)([]byte, error){
	input := new(bytes.Buffer)
	input.Write(msg)
	output := new(bytes.Buffer)
	err := SignStream(input, output, passphrase, privKey)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func SignStream(in io.Reader, out io.Writer, passphrase []byte, privKey [][]byte) error{
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
func VerifyBundle(signatureIncludingData []byte, pubkey [][]byte)(bool, error){
	regexRes := sigWithDataReg.FindAllSubmatch(signatureIncludingData, 1)
	if len(regexRes)==1 && len(regexRes[0])==3{
		return Verify(regexRes[0][1], regexRes[0][2], pubkey)
	}
	return false, errors.New("couldn't parse the signed data of your input!")
}

func Verify(data, signature []byte, pubKey [][]byte)(bool, error){
	return VerifyStream(bytes.NewBuffer(data), bytes.NewBuffer(signature), pubKey)
}

func VerifyStream(dataReader, signatureReader io.Reader, pubKey [][]byte)(bool, error){
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

func EncryptStream(in io.Reader, out io.Writer, pubKey [][]byte) (int64, error){
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

func Decrypt(msg, passphrase, privKey []byte) ([]byte, error){
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

func ReadPublicKey(passphrase, privKey []byte) ([]byte, error){
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

func ReadIdentity(pubKey [][]byte) ([]map[string]string, error){
	entitylist, err := readKeys(pubKey)
	if err != nil {
		return nil, err
	}
	var re = regexp.MustCompile(`(.*?) <(.*?)>`)
	var resultArray  = make([]map[string]string, len(entitylist), len(entitylist))
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

func WriteIdentity(pw, privKey []byte, name, comment, email string) (map[string][]byte, error){
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
		key.SerializePrivate(ar, nil)
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
		for _, subkey := range e.Subkeys {
			err := subkey.Sig.SignKey(subkey.PublicKey, e.PrivateKey, nil)
			if err != nil {
				fmt.Println(err)
				return nil, err
			}
		}
	}
	if len(entitylist)== 1 {
		res["private"] = wrff(entitylist[0])
		res["public"] = wrf(entitylist[0])
		return res, nil
	}

	return nil, errors.New("not implemented")
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

