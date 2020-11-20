package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoSecretStreamHeaderBytes = int(C.crypto_secretstream_xchacha20poly1305_headerbytes())
	cryptoSecretStreamKeyBytes    = int(C.crypto_secretstream_xchacha20poly1305_keybytes())
	cryptoSecretStreamTagMessage  = uint8(C.crypto_secretstream_xchacha20poly1305_tag_message())
	cryptoSecretStreamTagPush     = uint8(C.crypto_secretstream_xchacha20poly1305_tag_push())
	cryptoSecretStreamTagReKey    = uint8(C.crypto_secretstream_xchacha20poly1305_tag_rekey())
	cryptoSecretStreamTagFinal    = uint8(C.crypto_secretstream_xchacha20poly1305_tag_final())
	cryptoSecretStreamABytes      = uint8(C.crypto_secretstream_xchacha20poly1305_abytes())
)

type CryptoSecretStreamKey struct {
	Bytes
}

func (c CryptoSecretStreamKey) Size() int {
	return cryptoSecretStreamKeyBytes
}

type CryptoSecretStreamState C.crypto_secretstream_xchacha20poly1305_state

type CryptoSecretStreamHeader struct {
	Bytes
}

func (CryptoSecretStreamHeader) Size() int {
	return cryptoSecretStreamHeaderBytes
}

func (state CryptoSecretStreamState) InitPush(key CryptoSecretStreamKey) CryptoSecretStreamHeader {
	var header CryptoSecretStreamHeader
	header.Bytes = make([]byte, header.Size())
	if int(C.crypto_secretstream_xchacha20poly1305_init_push(
		(*C.crypto_secretstream_xchacha20poly1305_state)(&state),
		(*C.uchar)(&header.Bytes[0]),
		(*C.uchar)(&key.Bytes[0]),
	)) != 0 {
		panic("sodium")
	}
	return header
}

func (state CryptoSecretStreamState) Push(message []uint8) []byte {
	messageLen := uint64(len(message))
	encrypted := make([]uint8, len(message)+int(cryptoSecretStreamABytes))
	if int(C.crypto_secretstream_xchacha20poly1305_push(
		(*C.crypto_secretstream_xchacha20poly1305_state)(&state),
		(*C.uchar)(&encrypted[0]),
		(*C.ulonglong)(nil),
		(*C.uchar)(&message[0]),
		(C.ulonglong)(messageLen),
		(*C.uchar)(nil),
		(C.ulonglong)(0),
		(C.uchar)(0),
	)) != 0 {
		panic("sodium")
	}
	return encrypted
}
