//2017年7月23日16:02:55 czn
package main

import(
	"fmt"
	"encoding/binary"
)


var sm3_len uint32	= 256
var sm3_t1	uint32 = 0x79cc4519
var sm3_t2	uint32 = 0x7a879d8a
var sm3_iva	uint32 = 0x7380166f
var sm3_ivb uint32 = 0x4914b2b9
var sm3_ivc uint32 = 0x172442d7
var sm3_ivd uint32 = 0xda8a0600
var sm3_ive uint32 = 0xa96f30bc
var sm3_ivf uint32 = 0x163138aa
var sm3_ivg uint32 = 0xe38dee4d
var sm3_ivh uint32 = 0xb0fb0e4e

func sm3_rotl32(x ,y uint32) uint32{
	return (x << y) | (x >> (32 - y))
}

/*func sm3_rotr32(x ,y uint32) uint32{
	return (x >> y) | (x << (32 - y))
}*/

func sm3_p1(x uint32) uint32{
	return x ^ sm3_rotl32(x,15) ^ sm3_rotl32(x,23)
}

func sm3_p0(x uint32) uint32{
	return x ^ sm3_rotl32(x,9) ^ sm3_rotl32(x,17)
}

func sm3_ff0(a ,b ,c uint32) uint32{
	return a ^ b ^ c
}

func sm3_ff1(a ,b ,c uint32) uint32{
	return (a & b) | (a & c) | (b & c)
}

func sm3_gg0(a ,b ,c uint32) uint32{
	return a ^ b ^ c
}

func sm3_gg1(a ,b ,c uint32) uint32{
	return (a & b) | ((^a) & c)
}

type sm3_state struct {
	state [8] uint32
	length uint32
	curlen uint32
	buf	[64] uint8
}

func bitow(bi [] uint8, w [68] uint32) [68]uint32{
	var i int
	var tmp uint32
	var bi32 = make([]uint32, 16, 16)
	for i != 16 {
		bi32[i] = binary.LittleEndian.Uint32([]byte(bi[4*i : 4*i+4]))
		i++
	}
	for i=0;i<=15;i++{
		w[i] = bi32[i]
	}
	for i=16;i<=67;i++{
		tmp = w[i-16] ^ w[i-9] ^sm3_rotl32(w[i-3], 15)
		w[i] = sm3_p1(tmp) ^ sm3_rotl32(w[i-13], 7) ^ w[i-6]
	}
	return w
}

func wtow1(w [68] uint32, w1 [64] uint32) ([68]uint32,[64]uint32){
	var i int

	for i=0;i<=63;i++{
		w1[i] = w[i] ^ w[i+4]
	}
	return w,w1
}

func cf(w [68] uint32, w1 [64] uint32, v [8] uint32) [8]uint32{
	var ss1 uint32
	var ss2 uint32
	var tt1 uint32
	var tt2 uint32
	var a,b,c,d,e,f,g,h uint32
	var t uint32 = sm3_t1
	var ff,gg uint32
	var j int

	a = v[0]
	b = v[1]
	c = v[2]
	d = v[3]
	e = v[4]
	f = v[5]
	g = v[6]
	h = v[7]

	for j=0;j<=63;j++ {
		if j == 0 {
			t = sm3_t1
		} else if j == 16 {
			t = sm3_rotl32(sm3_t2, 16)
		} else {
			t = sm3_rotl32(t, 1)
		}

		ss1 = sm3_rotl32(sm3_rotl32(a, 12) + e + t, 7)

		ss2 = ss1 ^ sm3_rotl32(a, 12)

		if j <= 15 {
			ff = sm3_ff0(a, b, c)
		} else {
			ff = sm3_ff1(a, b, c)
		}
		tt1 = ff + d + ss2 + w1[j]

		if j <= 15 {
			gg = sm3_gg0(e, f, g)
		} else {
			gg = sm3_gg1(e, f, g)
		}
		tt2 = gg + h + ss1 + w[j]

		d = c
		c = sm3_rotl32(b, 9)
		b = a
		a = tt1
		h = g
		g = sm3_rotl32(f, 19)
		f = e
		e = sm3_p0(tt2)
	}

	v[0] = a ^ v[0]
	v[1] = b ^ v[1]
	v[2] = c ^ v[2]
	v[3] = d ^ v[3]
	v[4] = e ^ v[4]
	v[5] = f ^ v[5]
	v[6] = g ^ v[6]
	v[7] = h ^ v[7]
	return v
}

func bigendian(src [] uint8, bytelen uint32, des [] uint8){
	var tmp uint8 = 0
	var i uint32 = 0

	for i=0;i<bytelen/4;i++{
		tmp = des[4*i]
		des[4*i] = src[4*i+3]
		src[4*i+3] = tmp

		tmp = des[4*i+1]
		des[4*i+1] = src[4*i+2]
		des[4*i+2] = tmp
	}
}

func sm3_init(md *sm3_state){
	md.curlen = 0
	md.length = 0
	md.state[0] = sm3_iva
	md.state[1] = sm3_ivb
	md.state[2] = sm3_ivc
	md.state[3] = sm3_ivd
	md.state[4] = sm3_ive
	md.state[5] = sm3_ivf
	md.state[6] = sm3_ivg
	md.state[7] = sm3_ivh
}

func sm3_compress(md *sm3_state){
	var w [68] uint32
	var w1 [64] uint32
	bigendian(md.buf[:], 64, md.buf[:])
	w = bitow(md.buf[:], w)
	w,w1 = wtow1(w, w1)
	md.state = cf(w, w1, md.state)
}

func sm3_process(md *sm3_state, buf [] uint8, len int){
	var i int
	for i = 0;len != 0;len--{
		md.buf[md.curlen] = buf[i]
		i++
		md.curlen++

		if md.curlen == 64{
			sm3_compress(md)
			md.length += 512
			md.curlen = 0
		}
	}
}

func sm3_done(md *sm3_state, hash []uint8){
	var i int
	var tmp =make([] uint8,4,4)
	md.length += md.curlen << 3

	md.buf[md.curlen] = 0x80
	md.curlen++

	if md.curlen > 56{
		for md.curlen < 64{
			md.buf[md.curlen] = 0
			md.curlen++
		}
		sm3_compress(md)
		md.curlen = 0
	}

	for md.curlen < 56{
		md.buf[md.curlen] = 0
		md.curlen++
	}

	for i=56;i<60;i++{
		md.buf[i] = 0
	}

	md.buf[63] = uint8(md.length & 0xff)
	md.buf[62] = uint8(md.length >> 8 & 0xff)
	md.buf[61] = uint8(md.length >> 16 & 0xff)
	md.buf[60] = uint8(md.length >> 24 & 0xff)

	sm3_compress(md)

	for i=0;i!=8;i++ {
		binary.BigEndian.PutUint32(tmp, md.state[i])
		hash[4*i] = tmp[0]
		hash[4*i+1] = tmp[1]
		hash[4*i+2] = tmp[2]
		hash[4*i+3] = tmp[3]
	}
}

func sm3_256(buf [] uint8, len int, hash [] uint8){
	var md sm3_state
	sm3_init(&md)
	sm3_process(&md, buf, len)
	sm3_done(&md, hash)
}

func memcpy ( buf1 []uint8, buf2 []uint8,count int) {

	if count == 0{
		return
	}
	var i int =0
	for i < count  {
		buf1[i]=buf2[i]
		i++
	}
}

func memcmp ( buf1 []uint8, buf2 []uint8,count int) int {

	if count == 0{
		return 0
	}
	var i int =0

	for buf1[i] == buf2[i]  {
		if i == count-1{
			break
		}
		i ++
	}
	return int(buf1[i] - buf2[i])
}

func main(){//test
	var msg1  = [3] uint8 {0x61,0x62,0x63}
	var msglen1 int = 3
	var msghash1 = make([]uint8,32,32)
	var stdhash1 = [32] uint8 {0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
		                       0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0}
	var msg2 = [64] uint8 {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
						   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
						   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
						   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64}
	var msglen2 int = 64
	var msghash2 = make([]uint8,32,32)
	var stdhash2 = [32] uint8 {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
							   0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32}
	sm3_256(msg1[:], msglen1, msghash1)
	sm3_256(msg2[:], msglen2, msghash2)
	var a int = memcmp(msghash1, stdhash1[:], 32)
	var b int = memcmp(msghash2, stdhash2[:], 32)
	if a==0 && b==0{
		fmt.Println("right!")
	}else {
		fmt.Println("error!")
	}


}