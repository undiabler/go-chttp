package chttp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAes test aes works as expected
func TestAes(t *testing.T) {

	pass := "password123"
	secretData := "my pin is 1234"

	// key := passToKey([]byte(pass))
	// t.Logf("%v", key)

	aes, err := PassEncrypt([]byte(pass), []byte(secretData))
	assert.NoError(t, err, "crypt is not working")
	t.Logf("Aes encoded: %s", aes)

	decr, err := PassDecrypt([]byte(pass), aes)
	assert.NoError(t, err, "decrypt is not working")

	assert.Equal(t, secretData, string(decr), "data corrupted")

	_, errFail1 := PassDecrypt([]byte(pass+"random"), aes)
	assert.Error(t, errFail1, "must be invalid")

	_, errFail2 := PassDecrypt([]byte(pass), append(aes, byte(0x1)))
	assert.Error(t, errFail2, "must be corrupted")
}

// TestTools test aditional funcs
func TestTools(t *testing.T) {

	src := "password"
	abbr := Ptchk(src)
	assert.Equal(t, "psswrd", abbr, "function not working properly")

	srcIP := "127.0.0.1"
	masked := MaskIP(srcIP)
	assert.Equal(t, "127***1", masked, "mask ip is not working")
}
