package sodium

/*
	Author:
	@sokket 2020
*/

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

func (state *CryptoSecretStreamState) InitPush(key CryptoSecretStreamKey) CryptoSecretStreamHeader {
	var header CryptoSecretStreamHeader
	header.Bytes = make([]byte, header.Size())
	if int(C.crypto_secretstream_xchacha20poly1305_init_push(
		(*C.crypto_secretstream_xchacha20poly1305_state)(state),
		(*C.uchar)(&header.Bytes[0]),
		(*C.uchar)(&key.Bytes[0]),
	)) != 0 {
		panic("sodium")
	}
	return header
}

func (state *CryptoSecretStreamState) Push(message []uint8) []byte {
	return state.push(message, cryptoSecretStreamTagMessage)
}

func (state *CryptoSecretStreamState) PushFinal(message []uint8) []byte {
	return state.push(message, cryptoSecretStreamTagFinal)
}

func (state *CryptoSecretStreamState) PushEnd(message []uint8) []byte {
	return state.push(message, cryptoSecretStreamTagPush)
}

func (state *CryptoSecretStreamState) PushReKey(message []uint8) []byte {
	return state.push(message, cryptoSecretStreamTagReKey)
}

func (state *CryptoSecretStreamState) push(message []uint8, tag uint8) []byte {
	messageLen := uint64(len(message))
	encrypted := make([]uint8, len(message)+int(cryptoSecretStreamABytes))
	if int(C.crypto_secretstream_xchacha20poly1305_push(
		(*C.crypto_secretstream_xchacha20poly1305_state)(state),
		(*C.uchar)(&encrypted[0]),
		(*C.ulonglong)(nil),
		(*C.uchar)(&message[0]),
		(C.ulonglong)(messageLen),
		(*C.uchar)(nil),
		(C.ulonglong)(0),
		(C.uchar)(tag),
	)) != 0 {
		panic("sodium")
	}
	return encrypted
}

type CryptoSecretStreamChunk struct {
	Final bool
	End   bool
	ReKey bool
	Data  []byte
}

func (state *CryptoSecretStreamState) InitPull(key CryptoSecretStreamKey, header CryptoSecretStreamHeader) error {
	if int(C.crypto_secretstream_xchacha20poly1305_init_pull(
		(*C.crypto_secretstream_xchacha20poly1305_state)(state),
		(*C.uchar)(&header.Bytes[0]),
		(*C.uchar)(&key.Bytes[0]),
	)) != 0 {
		return ErrInvalidHeader
	}
	return nil
}

func (state *CryptoSecretStreamState) Pull(encrypted []uint8) (CryptoSecretStreamChunk, error) {
	encryptedLen := uint64(len(encrypted))
	decrypted := make([]uint8, len(encrypted)-int(cryptoSecretStreamABytes))
	var tag uint8
	if int(C.crypto_secretstream_xchacha20poly1305_pull(
		(*C.crypto_secretstream_xchacha20poly1305_state)(state),
		(*C.uchar)(&decrypted[0]),
		(*C.ulonglong)(nil),
		(*C.uchar)(&tag),
		(*C.uchar)(&encrypted[0]),
		(C.ulonglong)(encryptedLen),
		(*C.uchar)(nil),
		(C.ulonglong)(0),
	)) != 0 {
		return CryptoSecretStreamChunk{}, ErrDecryptAEAD
	}

	return CryptoSecretStreamChunk{
		Final: tag == cryptoSecretStreamTagFinal,
		End:   tag == cryptoSecretStreamTagPush,
		ReKey: tag == cryptoSecretStreamTagReKey,
		Data:  decrypted,
	}, nil
}
