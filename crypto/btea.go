package crypto

import "encoding/binary"

const bteaDelta uint32 = 0x9E3779B9

// BTEA is the corrected block TEA (XXTEA) cipher over little-endian words.
type BTEA struct {
	Key [16]byte

	// Rounds is the number of full cycles. 0 uses 6 + 52/n.
	Rounds int
}

func (c BTEA) rounds(n int) int {
	if c.Rounds > 0 {
		return c.Rounds
	}

	return 6 + 52/n
}

func (c BTEA) keyWords() [4]uint32 {
	var k [4]uint32

	for i := range k {
		k[i] = binary.LittleEndian.Uint32(c.Key[i*4 : i*4+4])
	}

	return k
}

func loadWords(data []byte) []uint32 {
	v := make([]uint32, len(data)/4)

	for i := range v {
		v[i] = binary.LittleEndian.Uint32(data[i*4 : i*4+4])
	}

	return v
}

func storeWords(data []byte, v []uint32) {
	for i := range v {
		binary.LittleEndian.PutUint32(data[i*4:i*4+4], v[i])
	}
}

func (c BTEA) Decrypt(data []byte) bool {
	if len(data) < 8 || len(data)%4 != 0 {
		return false
	}

	v := loadWords(data)
	k := c.keyWords()
	n := len(v)
	rounds := c.rounds(n)

	sum := uint32(rounds) * bteaDelta
	y := v[0]

	for round := 0; round < rounds; round++ {
		e := (sum >> 2) & 3

		for p := n - 1; p > 0; p-- {
			z := v[p-1]
			v[p] -= bteaMX(z, y, sum, k, e, uint32(p))
			y = v[p]
		}

		z := v[n-1]
		v[0] -= bteaMX(z, y, sum, k, e, 0)
		y = v[0]
		sum -= bteaDelta
	}

	storeWords(data, v)

	return true
}

// Encrypt is the inverse of Decrypt. The sniffer never sends traffic; it is
// kept for tests and for building fixtures.
func (c BTEA) Encrypt(data []byte) bool {
	if len(data) < 8 || len(data)%4 != 0 {
		return false
	}

	v := loadWords(data)
	k := c.keyWords()
	n := len(v)
	rounds := c.rounds(n)

	var sum uint32
	z := v[n-1]

	for round := 0; round < rounds; round++ {
		sum += bteaDelta
		e := (sum >> 2) & 3

		for p := 0; p < n-1; p++ {
			y := v[p+1]
			v[p] += bteaMX(z, y, sum, k, e, uint32(p))
			z = v[p]
		}

		y := v[0]
		v[n-1] += bteaMX(z, y, sum, k, e, uint32(n-1))
		z = v[n-1]
	}

	storeWords(data, v)

	return true
}

func bteaMX(
	z uint32,
	y uint32,
	sum uint32,
	key [4]uint32,
	e uint32,
	p uint32,
) uint32 {
	return (((z >> 5) ^ (y << 2)) +
		((y >> 3) ^ (z << 4))) ^
		((sum ^ y) +
			(key[(p&3)^e] ^ z))
}
