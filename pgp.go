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
)
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

	entity := entitylist[0]
	fmt.Println("public key from armored string:", entity.Identities)

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

func Decrypt(msg []byte, passphrase []byte, privKey []byte) ([]byte, error){
	// Read armored private key into type EntityList
	// An EntityList contains one or more Entities.
	// This assumes there is only one Entity involved
	//fmt.Println(bytes.NewBufferString(privateKey))
	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(privKey))
	if err != nil {
		return nil, err;
	}
	entity := entitylist[0]
	fmt.Println("Private key from armored string:", entity.Identities)

	// Decrypt private key using passphrase
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

