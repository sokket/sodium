package sodium

import (
	"crypto/rand"
	"fmt"
	"testing"
)

var m = Bytes(make([]byte, 1024))

func TestInit(t *testing.T) {
	rand.Read(m)
}

func TestByte(t *testing.T) {
	b := Bytes{}
	bp, bl := b.plen()
	if bp != nil {
		t.FailNow()
	}
	if bl != 0 {
		t.FailNow()
	}

	b = Bytes(make([]byte, 0, 1024))
	bp, bl = b.plen()
	if bp != nil {
		t.FailNow()
	}
	if bl != 0 {
		t.FailNow()
	}

	b = Bytes(make([]byte, 1024))
	bp, bl = b.plen()
	if bp == nil {
		t.FailNow()
	}
	if bl != 1024 {
		t.FailNow()
	}
}

func ExampleBytes_Auth() {
	key := MACKey{}
	Randomize(&key)
	mac := m.Auth(key)

	err := m.AuthVerify(mac, key)
	fmt.Println(err)
	//Output: <nil>
}

func ExampleSeedSignKP() {
	seed := SignSeed{}
	Randomize(&seed)
	kp1 := SeedSignKP(seed)
	kp2 := SeedSignKP(seed)
	s1 := kp1.SecretKey
	s2 := kp2.SecretKey

	s := s1.Seed()
	pk1 := s1.PublicKey()

	fmt.Println(MemCmp(s1.Bytes, s2.Bytes, s1.Length()) == 0)
	fmt.Println(MemCmp(s.Bytes, seed.Bytes, seed.Length()) == 0)
	fmt.Println(MemCmp(pk1.Bytes, kp1.PublicKey.Bytes, pk1.Length()) == 0)
	//Output: true
	//true
	//true
}

func ExampleBytes_SignDetached() {
	kp := MakeSignKP()
	sm := m.Sign(kp.SecretKey)

	om, err := sm.SignOpen(kp.PublicKey)
	sig := m.SignDetached(kp.SecretKey)

	fmt.Println(err)
	fmt.Println(MemCmp(om, m, m.Length()) == 0)
	fmt.Println(MemCmp(sig.Bytes, sm, sig.Length()) == 0)

	err = m.SignVerifyDetached(sig, kp.PublicKey)
	fmt.Println(err)
	//Output: <nil>
	//true
	//true
	//<nil>
}

func ExampleMakeSignState() {
	kp := MakeSignKP()

	s_a := MakeSignState()
	s_a.Update(m)

	siga := s_a.Sign(kp.SecretKey)

	s_b := MakeSignState()
	s_b.Update(m)

	err := s_b.Verify(siga, kp.PublicKey)
	fmt.Println(err)
	//Output: <nil>
}

func ExampleSeedBoxKP() {
	seed := BoxSeed{}
	Randomize(&seed)
	kp1 := SeedBoxKP(seed)
	kp2 := SeedBoxKP(seed)
	s1 := kp1.SecretKey
	s2 := kp2.SecretKey

	fmt.Println(MemCmp(s1.Bytes, s2.Bytes, s1.Length()) == 0)
	//Output: true
}

func ExampleBytes_SealedBox() {
	kp := MakeBoxKP()

	n := BoxNonce{}
	Randomize(&n)

	c := m.SealedBox(kp.PublicKey)
	om, err := c.SealedBoxOpen(kp)

	fmt.Println(err)
	fmt.Println(MemCmp(om, m, m.Length()) == 0)
	//Output: <nil>
	//true
}

func ExampleBytes_Box() {
	rkp := MakeBoxKP()
	skp := MakeBoxKP()

	n := BoxNonce{}
	Randomize(&n)

	bc := m.Box(n, rkp.PublicKey, skp.SecretKey)
	bom, err := bc.BoxOpen(n, skp.PublicKey, rkp.SecretKey)

	fmt.Println(err)
	fmt.Println(MemCmp(bom, m, m.Length()) == 0)
	//Output: <nil>
	//true
}

func ExampleBytes_BoxDetached() {
	rkp := MakeBoxKP()
	skp := MakeBoxKP()

	n := BoxNonce{}
	Randomize(&n)

	mac, bcd := m.BoxDetached(n, rkp.PublicKey, skp.SecretKey)
	bomd, err := bcd.BoxOpenDetached(mac, n, skp.PublicKey, rkp.SecretKey)

	fmt.Println(err)
	fmt.Println(MemCmp(bomd, m, m.Length()) == 0)
	//Output: <nil>
	//true
}

func ExampleBoxSecretKey_PublicKey() {
	kp := MakeBoxKP()
	pk := kp.SecretKey.PublicKey()

	fmt.Println(MemCmp(kp.PublicKey.Bytes, pk.Bytes, pk.Length()) == 0)
	//Output: true
}

func ExampleNewGenericHashKeyed() {
	kp := MakeBoxKP()
	key := GenericHashKey{kp.SecretKey.Bytes}

	h := NewGenericHashKeyed(48, key)
	h.Write(m)
	sh := h.Sum(nil)

	he := NewGenericHash(48)
	he.Write(m)
	she := he.Sum(nil)

	fmt.Println(len(sh))
	fmt.Println(len(she))
	fmt.Println((MemCmp(sh, she, len(sh))) == 0)
	//Output: 48
	//48
	//false
}

func ExampleBytes_Shorthash() {
	key := ShortHashKey{}
	Randomize(&key)

	m := Bytes(`short message`)
	hash := m.Shorthash(key)
	fmt.Println(hash.Length())
	//Output: 8
}

func ExampleBytes_SecretBox() {
	key := SecretBoxKey{}
	Randomize(&key)
	n := SecretBoxNonce{}
	Randomize(&n)

	c := m.SecretBox(n, key)
	md, err := c.SecretBoxOpen(n, key)
	fmt.Println(err)
	fmt.Println(MemCmp(md, m, m.Length()) == 0)
	//Output: <nil>
	//true
}

func ExampleBytes_SecretBoxDetached() {
	key := SecretBoxKey{}
	Randomize(&key)
	n := SecretBoxNonce{}
	Randomize(&n)

	c, mac := m.SecretBoxDetached(n, key)
	md, err := c.SecretBoxOpenDetached(mac, n, key)
	fmt.Println(err)
	fmt.Println(MemCmp(md, m, m.Length()) == 0)
	//Output: <nil>
	//true
}

func ExampleBytes_AEADCPEncrypt() {
	key := AEADCPKey{}
	Randomize(&key)

	n := AEADCPNonce{}
	Randomize(&n)

	ad := Bytes(`addtional data`)

	e := m.AEADCPEncrypt(ad, n, key)

	md, err := e.AEADCPDecrypt(ad, n, key)
	fmt.Println(err)
	fmt.Println(MemCmp(md, m, m.Length()) == 0)
	//Output: <nil>
	//true
}

func ExampleBytes_AEADCPVerify() {
	key := AEADCPKey{}
	Randomize(&key)

	n := AEADCPNonce{}
	Randomize(&n)

	ad := Bytes(`addtional data`)

	e := m.AEADCPEncrypt(ad, n, key)

	err := e.AEADCPVerify(ad, n, key)
	fmt.Println(err)
	//Output: <nil>
}

func ExampleBytes_AEADCPEncryptDetached() {
	key := AEADCPKey{}
	Randomize(&key)

	n := AEADCPNonce{}
	Randomize(&n)

	ad := Bytes(`addtional data`)

	e, mac := m.AEADCPEncryptDetached(ad, n, key)

	md, err := e.AEADCPDecryptDetached(mac, ad, n, key)
	fmt.Println(err)
	fmt.Println(MemCmp(md, m, m.Length()) == 0)
	//Output: <nil>
	//true
}

func ExampleBytes_AEADCPVerifyDetached() {
	key := AEADCPKey{}
	Randomize(&key)

	n := AEADCPNonce{}
	Randomize(&n)

	ad := Bytes(`addtional data`)

	e, mac := m.AEADCPEncryptDetached(ad, n, key)

	err := e.AEADCPVerifyDetached(mac, ad, n, key)
	fmt.Println(err)
	//Output: <nil>
}

func ExamplePWHashStore() {
	s := PWHashStore("test")
	str := s.Value()        // str for store
	t := LoadPWHashStr(str) // load from storage
	err := t.PWHashVerify("test")

	fmt.Println(err)
	//Output: <nil>
}

func ExampleSignKP_ToBox() {
	skp := MakeSignKP()
	bkp := skp.ToBox()
	rkp := MakeBoxKP()

	sb := skp.SecretKey.ToBox()
	pb := skp.PublicKey.ToBox()

	fmt.Println(MemCmp(bkp.SecretKey.Bytes, sb.Bytes, bkp.SecretKey.Length()) == 0)
	fmt.Println(MemCmp(bkp.PublicKey.Bytes, pb.Bytes, bkp.PublicKey.Length()) == 0)

	n := BoxNonce{}
	Randomize(&n)

	bc := m.Box(n, rkp.PublicKey, bkp.SecretKey)
	bom, err := bc.BoxOpen(n, bkp.PublicKey, rkp.SecretKey)

	fmt.Println(err)
	fmt.Println(MemCmp(bom, m, m.Length()) == 0)

	//Output: true
	//true
	//<nil>
	//true
}

func ExampleMasterKey_Derive() {
	mk := MakeMasterKey()
	context := MakeKeyContext("testblablabla") // only first CryptoKDFContextBytes is used
	fmt.Println(context)
	sk := mk.Derive(CryptoKDFBytesMin, 0, context)

	fmt.Println(sk.Length() == CryptoKDFBytesMin)
	//Output: testblab
	//true
}

func ExampleMakeKXKP() {
	skp := MakeKXKP()
	ckp := MakeKXKP()

	sss, _ := skp.ServerSessionKeys(ckp.PublicKey)
	css, _ := ckp.ClientSessionKeys(skp.PublicKey)

	fmt.Println(MemCmp(sss.Tx.Bytes, css.Rx.Bytes, sss.Tx.Size()) == 0)
	fmt.Println(MemCmp(sss.Rx.Bytes, css.Tx.Bytes, sss.Rx.Size()) == 0)

	fmt.Println(MemCmp(sss.Tx.Bytes, sss.Rx.Bytes, sss.Tx.Size()) == 0)
	fmt.Println(MemCmp(css.Tx.Bytes, css.Rx.Bytes, css.Tx.Size()) == 0)
	//Output: true
	//true
	//false
	//false
}

func TestStream(t *testing.T) {
	var key CryptoSecretStreamKey
	Randomize(&key)

	state := new(CryptoSecretStreamState)
	header := state.InitPush(key)
	encrypted := state.Push([]byte("Hello world!"))

	pullState := new(CryptoSecretStreamState)
	_ = pullState.InitPull(key, header)
	chunk, _ := pullState.Pull(encrypted)

	fmt.Println(string(chunk.Data))
	//Output: Hello world!
}
