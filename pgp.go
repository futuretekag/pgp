package pgp

import (
	"bytes"
	"fmt"
	"errors"
	"io/ioutil"
	"regexp"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"time"
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

func Create(name, email string, expiry time.Duration) (map[string][]byte, error){
	// Create the key
	key, err := openpgp.NewEntity(name, "", email, nil)
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

		err := id.SelfSignature.SignUserId(id.UserId.Id, key.PrimaryKey, key.PrivateKey, nil)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}

	// Self-sign the Subkeys
	for _, subkey := range key.Subkeys {
		subkey.Sig.KeyLifetimeSecs = &dur
		err := subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, nil)
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

// TODO make it work
func Sign(msg []byte, passphrase []byte, privKey [][]byte)([]byte, error){
	entitylist, err := readKeys(privKey);
	if err != nil {
		return nil, err
	}
	input := new(bytes.Buffer)
	input.Write(msg)
	output := new(bytes.Buffer)
	for _, e := range entitylist {
		err = e.PrivateKey.Decrypt(passphrase)
		if err != nil {
			return nil, err
		}
	}
	err = openpgp.ArmoredDetachSignText(output, entitylist[0], input, nil)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
// TODO make it work
func Verify(msg []byte, pubKey [][]byte)(bool, error){
	entitylist, err := readKeys(pubKey);
	if err != nil {
		return false, err
	}
	input := new(bytes.Buffer)
	input.Write(msg)
	block, err := armor.Decode(input)

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
	err = entitylist[0].PrimaryKey.VerifySignature(hash, sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func Encrypt(msg []byte, pubKey [][]byte) ([]byte, error) {
	entitylist, err := readKeys(pubKey);

	//entity := entitylist[0]
	//fmt.Println("public key from armored string:", entity.Identities)

	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entitylist, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(msg)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	armored := new(bytes.Buffer)

	w, err = armor.Encode(armored, "PGP MESSAGE", make(map[string]string))
	_, err = w.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	return armored.Bytes(), nil
}

func Decrypt(msg, passphrase, privKey []byte) ([]byte, error){
	// Read armored private key into type EntityList
	// An EntityList contains one or more Entities.
	// This assumes there is only one Entity involved
	//fmt.Println(bytes.NewBufferString(privateKey))
	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(privKey))
	if err != nil {
		return nil, err;
	}
	entity := entitylist[0]
	//fmt.Println("Private key from armored string:", entity.Identities)

	// Decrypt private key using passphrase
	if passphrase != nil{
		if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
			fmt.Println("Decrypting private key using passphrase")
			err := entity.PrivateKey.Decrypt(passphrase)
			if err != nil {
				return nil, err;
			}
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
				err := subkey.PrivateKey.Decrypt(passphrase)
				if err != nil {
					return nil, err;
				}
			}
		}
	}

	// Decrypt armor encrypted message using decrypted private key
	decbuf := bytes.NewBuffer(msg)
	result, err := armor.Decode(decbuf)
	if err != nil {
		return nil, err;
	}

	md, err := openpgp.ReadMessage(result.Body, entitylist, nil /* no prompt */, nil)
	if err != nil {
		return nil, err;
	}

	return ioutil.ReadAll(md.UnverifiedBody)
}

func ReadIdentity(pubKey [][]byte) ([]map[string]string, error){
	entitylist, err := readKeys(pubKey);
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

func readKeys(keys [][]byte) (el openpgp.EntityList, err error) {
	for _, key := range keys {
		entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(key))
		if err != nil {
			return nil, err;
		}
		for _, e := range entitylist {
			el = append(el, e)
		}
	}
	return el, nil;
}

