package SM2

func Test_Zero(x Big) int {
	var zero Big
	zero = Mirvar(0)
	if compare(x, zero) == 0 {
		return 1
	} else {
		return 0
	}
}

func Test_n(x Big)int {
	// Bytes_to_big(32,SM2_n,n);
	if compare(x, n) == 0 {
		return 1
	} else {
		return 0
	}
}

func Test_Range(x Big)int {
	var one, decr_n Big
	one = Mirvar(0)
	decr_n = Mirvar(0)
	convert(1, one)
	decr(n, 1, decr_n)
	if (compare(x, one) < 0) || (compare(x, decr_n) > 0) { //这里原本是(compare(x, one) < 0) | (compare(x, decr_n) > 0)
		return 1
	}
	return 0
}

func SM2_Sign(message []uint8,len int,ZA []uint8,rand []uint8,d []uint8,R []uint8,S []uint8) uint32 {
	
	a, b, n, p, Gx, Gy = para_a, para_b, para_n, para_p, para_Gx, para_Gy

	var hash [32]uint8
	var M_len int = len + int(SM3_len)/8
	var M []uint8 = nil
	//var i int
	var dA, r, s, e, k, KGx, KGy Big
	var rem, rk, z1, z2 Big
	var KG *Epoint

	dA = Mirvar(0)
	e = Mirvar(0)
	k = Mirvar(0)
	KGx = Mirvar(0)
	KGy = Mirvar(0)
	r = Mirvar(0)
	s = Mirvar(0)
	rem = Mirvar(0)
	rk = Mirvar(0)
	z1 = Mirvar(0)
	z2 = Mirvar(0)
	Bytes_to_big(SM2_NUMWORD, d, dA) //cinstr(dA,d);
	KG = Epoint_init()
	//step1,set M=ZA||M
	//M = (char *)malloc(sizeof(char) * (M_len + 1)) 记号
	M = make([]uint8,M_len+1)
	memcpy(M, ZA, int(SM3_len)/8)
	memcpy(M[SM3_len/8:], message, len)
	//step2,generate e=H(M)
	SM3_256(M, M_len, hash[:])
	Bytes_to_big(int(SM3_len)/8, hash[:], e)
	//step3:generate k
	Bytes_to_big(int(SM3_len)/8, rand, k)
	//step4:calculate kG
	ecurve_mult(k, G, KG)
	//step5:calculate r
	Epoint_get(KG, KGx, KGy)
	Add(e, KGx, r)

	Divide(r, n, rem)
	//judge r=0 or n+k=n?
	Add(r, k, rk)
	if Test_Zero(r)!=0 || Test_n(rk)!=0 {
		return ERR_GENERATE_R
	}
	//step6:generate s
	incr(dA, 1, z1)
	xgcd(z1, n, z1, z1, z1)
	Multiply(r, dA, z2)
	Divide(z2, n, rem)
	subtract(k, z2, z2)
	Add(z2, n, z2)
	Multiply(z1, z2, s)
	Divide(s, n, rem)
	//judge s=0?
	if Test_Zero(s)!=0 {
		return ERR_GENERATE_S
	}
	Big_to_bytes(SM2_NUMWORD, r, R, true)
	Big_to_bytes(SM2_NUMWORD, s, S, true)
	//free(M);
	return 0
}

func SM2_Verify(message []uint8,len int,ZA[]uint8,Px[]uint8,Py[]uint8,R[]uint8,S[]uint8) uint32 {
	var hash [32]uint8
	var M_len int = len + int(SM3_len)/8
	var M []uint8 = nil
	var PAx, PAy, r, s, e, t, rem, x1, y1, RR Big
	var PA, sG, tPA *Epoint

	PAx = Mirvar(0)
	PAy = Mirvar(0)
	r = Mirvar(0)
	s = Mirvar(0)
	e = Mirvar(0)
	t = Mirvar(0)
	x1 = Mirvar(0)
	y1 = Mirvar(0)
	rem = Mirvar(0)
	RR = Mirvar(0)
	PA = Epoint_init()
	sG = Epoint_init()
	tPA = Epoint_init()
	Bytes_to_big(SM2_NUMWORD, Px, PAx)
	Bytes_to_big(SM2_NUMWORD, Py, PAy)
	Bytes_to_big(SM2_NUMWORD, R, r)
	Bytes_to_big(SM2_NUMWORD, S, s)
	if Epoint_set(PAx, PAy, 0, PA) == 0 { //initialise public key
		return ERR_PUBKEY_INIT
	}
	//step1: test if r belong to [1,n-1]
	if Test_Range(r)!=0 {
		return ERR_OUTRANGE_R
	}
	//step2: test if s belong to [1,n-1]
	if Test_Range(s)!=0 {
		return ERR_OUTRANGE_S
	}
	//step3,generate M
	M = make([]uint8,M_len+1)
	memcpy(M, ZA, 32)
	memcpy(M[32:], message, len)
	//step4,generate e=H(M)
	SM3_256(M, M_len, hash[:])
	Bytes_to_big(int(SM3_len)/8, hash[:], e)
	//step5:generate t
	Add(r, s, t)
	Divide(t, n, rem)
	if Test_Zero(t)!=0 {
		return ERR_GENERATE_T
	}
	//step 6: generate(x1,y1)
	ecurve_mult(s, G, sG)
	ecurve_mult(t, PA, tPA)
	ecurve_add(sG, tPA)
	Epoint_get(tPA, x1, y1)
	//step7:generate RR
	Add(e, x1, RR)
	Divide(RR, n, rem)
	//free(M);
	if compare(RR, r) == 0 {
		return 0
	} else {
		return ERR_DATA_MEMCMP
	}
}
/*
func SM2_SelfCheck()int {
	//the private key
	var dA = [32]uint8{0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f,
					   0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8}
	var rand = [32]uint8{0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D,
						 0xCC, 0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21}
	//the public key
	 var xA=[32]uint8{0x09,0xf9,0xdf,0x31,0x1e,0x54,0x21,0xa1,0x50,0xdd,0x7d,0x16,0x1e,0x4b,0xc5,
	0xc6,0x72,0x17,0x9f,0xad,0x18,0x33,0xfc,0x07,0x6b,0xb0,0x8f,0xf3,0x56,0xf3,0x50,0x20};
	var yA=[32]uint8{0xcc,0xea,0x49,0x0c,0xe2,0x67,0x75,0xa5,0x2d,0xc6,0xea,0x71,0x8c,0xc1,0xaa,
	0x60,0x0a,0xed,0x05,0xfb,0xf3,0x5e,0x08,0x4a,0x66,0x32,0xf6,0x07,0x2d,0xa9,0xad,0x13};
	//var xA [32]uint8
	//var yA [32]uint8
	var r [32]uint8
	var s [32]uint8 // Signature424C 49 43 45 31 32 33 40 59 41 48 4F 4F 2E 43 4F 11
	var IDA = [18]uint8{0x42, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33, 0x40, 0x59, 0x41,
						0x48, 0x4F, 0x4F, 0x2E, 0x43, 0x4F,0x11} //ASCII code of userA's identification
	var IDA_len int = 18
	var ENTLA = [2]uint8{0x00, 0x90}      //the length of userA's identification,presentation in ASCII code
	str := "message digest"
	var message =[]uint8(str) 	//the message to be signed
	var len int = len(message)         //the length of message
	var ZA [32]uint8                  	//ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	N := IDA_len+2+SM2_NUMWORD*6
	var Msg = make([]uint8,N,N)                         //210=IDA_len+2+SM2_NUMWORD*6
	var temp int
	var mip *Miracl = Mirsys(10000, 16)
	mip.IOBASE = 16
	temp = SM2_KeyGeneration(dA[:], xA[:], yA[:])
	if temp != 0 {
		return temp
	}
	// ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA
	memcpy(Msg[:], ENTLA[:], 2)
	memcpy(Msg[2:N], IDA[:], IDA_len)
	memcpy(Msg[2+IDA_len:N], SM2_a[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD:N], SM2_b[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*2:N], SM2_Gx[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*3:N], SM2_Gy[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*4:N], xA[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*5:N], yA[:], SM2_NUMWORD)
	SM3_256(Msg[:], N, ZA[:])
	temp = SM2_Sign(message, len, ZA[:], rand[:], dA[:], r[:], s[:])
	if temp != 0 {
		//fmt.Print("s")
		return temp
	}
	temp = SM2_Verify(message, len, ZA[:], xA[:], yA[:], r[:], s[:])
	if temp != 0 {
		//fmt.Print("s")
		return temp
	}
	//fmt.Printf("%x\n",ZA)
	//fmt.Printf("%x\n",r)
	//fmt.Printf("%x\n",s)
	return 0
}
*/

func SM2_Si(user_priKey []uint8, IDA []uint8, Message []uint8) ([]uint8, []uint8, []uint8, uint32) {
	// ??? 1000 or 10000 ?
	var mip = Mirsys(10000, 16)
	mip.IOBASE = 16
	
	//initiate SM2 curve
	SM2_Init()

	SM2_rand := Rand_Gen( SM2_n[:] )
	//SM2_rand = []uint8{0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D,
			//			 0xCC, 0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21}

	var tmp uint32 = 0
	var PubKeyMerge = make([]uint8, SM2_NUMWORD*2)

	//generate key pair
	var PriKey, PubKey_x, PubKey_y Big
	var PubKey *Epoint

	PubKey_x = Mirvar(0)
	PubKey_y = Mirvar(0)
	PriKey = Mirvar(0)
	PubKey = Epoint_init()
	Bytes_to_big(len(user_priKey), user_priKey[:], PriKey) //PriKey is the standard private key's Big format

	tmp = SM2_KeyGeneration(PriKey, PubKey)
	if tmp != 0 {return nil, nil, nil, tmp}

	Epoint_get(PubKey, PubKey_x, PubKey_y)
	Big_to_bytes(SM2_NUMWORD, PubKey_x, PubKeyMerge[:], true)
	Big_to_bytes(SM2_NUMWORD, PubKey_y, PubKeyMerge[SM2_NUMWORD:], true)


	var r = make([]uint8, 32)
	var s = make([]uint8, 32)// Signature424C 49 43 45 31 32 33 40 59 41 48 4F 4F 2E 43 4F 11

	var IDA_len = len(IDA)
	//var ENTLA = [2]uint8{0x00, 0x90}      //the length of userA's identification,presentation in ASCII code
	var ENTLA = [2]uint8{ uint8((IDA_len*8)>>8), uint8(IDA_len*8)}      //the length of userA's identification,presentation in ASCII code
	
	var Msg_len int = len(Message)	//the length of Message
	var ZA [32]uint8		//ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	
	N := IDA_len+2+SM2_NUMWORD*6
	var Msg = make([]uint8,N,N)	//210=IDA_len+2+SM2_NUMWORD*6

	// ENTLA || IDA || a || b || Gx || Gy || xA || yA
	memcpy(Msg[:], ENTLA[:], 2)
	memcpy(Msg[2:N], IDA[:], IDA_len)
	memcpy(Msg[2+IDA_len:N], SM2_a[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD:N], SM2_b[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*2:N], SM2_Gx[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*3:N], SM2_Gy[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*4:N], PubKeyMerge[:], SM2_NUMWORD*2)	
	SM3_256(Msg[:], N, ZA[:])

	tmp = SM2_Sign(Message, Msg_len, ZA[:], SM2_rand, user_priKey[:], r[:], s[:])
	if tmp != 0 {return nil, nil, nil, tmp}

	return r, s, PubKeyMerge, 0
}

func SM2_Ve(user_pubKey []uint8, IDA []uint8, Message []uint8, R []uint8, S []uint8,) (bool, uint32) {
	// ??? 1000 or 10000 ?
	var mip = Mirsys(10000, 16)
	mip.IOBASE = 16

	//initiate SM2 curve
	SM2_Init()

	var tmp uint32 = 0

	var IDA_len = len(IDA)
	var ENTLA = [2]uint8{ uint8((IDA_len*8)>>8), uint8(IDA_len*8)}      //the length of userA's identification,presentation in ASCII code
	
	var Msg_len int = len(Message)	//the length of Message
	var ZA [32]uint8		//ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	
	N := IDA_len+2+SM2_NUMWORD*6
	Msg := make([]uint8,N,N)	//210=IDA_len+2+SM2_NUMWORD*6
	// ENTLA || IDA || a || b || Gx || Gy || xA || yA
	memcpy(Msg[:], ENTLA[:], 2)
	memcpy(Msg[2:N], IDA[:], IDA_len)
	memcpy(Msg[2+IDA_len:N], SM2_a[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD:N], SM2_b[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*2:N], SM2_Gx[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*3:N], SM2_Gy[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*4:N], user_pubKey[:], SM2_NUMWORD*2)	
	SM3_256(Msg[:], N, ZA[:])

	tmp = SM2_Verify(Message, Msg_len, ZA[:], user_pubKey[:SM2_NUMWORD], user_pubKey[SM2_NUMWORD:], R, S)
	if tmp != 0 {return false, tmp}

	return true, 0
}
