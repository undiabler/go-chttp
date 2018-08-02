package chttp

import (
	"crypto/sha256"
	"regexp"
	"strings"
)

var (
	rePtchk = regexp.MustCompile(`[aeiouy]`)
	reIP    = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+).(\d+)`)
)

// Ptchk - Function piatachok, make words understandable but not readable
// use for create abbreviations
func Ptchk(src string) string {
	ret := strings.Replace(src, ".", "-", -1)
	ret = rePtchk.ReplaceAllString(ret, "")
	return ret
}

func passToKey(pass []byte) []byte {
	b := sha256.Sum256(pass)
	return b[:]
}

// MaskIP - make abbreviations from ip 127.0.0.1 => 127***1
func MaskIP(src string) string {
	return reIP.ReplaceAllString(src, `$1***$4`)
}
