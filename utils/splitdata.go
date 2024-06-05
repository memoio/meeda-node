package utils

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

const ShardingLen = 127

func Pad127(in []byte, res []fr.Element) {
	if len(in) != 127 {
		if len(in) > 127 {
			in = in[:127]
		} else {
			padding := make([]byte, 127-len(in))
			in = append(in, padding...)
		}
	}

	tmp := make([]byte, 32)
	copy(tmp[:31], in[:31])

	t := in[31] >> 6
	tmp[31] = in[31] & 0x3f
	res[0].SetBytes(tmp)

	var v byte
	for i := 32; i < 64; i++ {
		v = in[i]
		tmp[i-32] = (v << 2) | t
		t = v >> 6
	}
	t = v >> 4
	tmp[31] &= 0x3f
	res[1].SetBytes(tmp)

	for i := 64; i < 96; i++ {
		v = in[i]
		tmp[i-64] = (v << 4) | t
		t = v >> 4
	}
	t = v >> 2
	tmp[31] &= 0x3f
	res[2].SetBytes(tmp)

	for i := 96; i < 127; i++ {
		v = in[i]
		tmp[i-96] = (v << 6) | t
		t = v >> 2
	}
	tmp[31] = t & 0x3f
	res[3].SetBytes(tmp)
}

func SplitData(data []byte) []fr.Element {
	num := (len(data)-1)/ShardingLen + 1

	atom := make([]fr.Element, num*4)

	padding := make([]byte, ShardingLen*num-len(data))
	data = append(data, padding...)

	for i := 0; i < num; i++ {
		Pad127(data[ShardingLen*i:ShardingLen*(i+1)], atom[4*i:4*i+4])
	}

	return atom
}
