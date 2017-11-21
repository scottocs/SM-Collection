/* SM4 加密解密, created by GJX */
package SM4
import (
	"fmt"
	"math/big"
	"strconv"
)
/* 变量定义区 */
/*  
	@CK 		固定参数, 用于秘钥扩展算法
	@SM4_Sbox 	S 盒为固定的 8 比特输入 8 比特输出的置换
	@SM4_FK 	系统参数, 用于秘钥扩展算法
 */
var SM4_CK = []uint32{0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299, 0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279}

var SM4_Sbox = []uint8{0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}

var SM4_FK = []uint32{0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC}


const OK uint32 = 0x00
const ERROR_IV uint32 = 0x01

/************************************************************
	Function:
		void SM4_KeySchedule(unsigned char MK[], unsigned int rk[]);
	Description:
		Generate round keys
	Calls:
	Called By:
		SM4_Encrypt;
		SM4_Decrypt;
	Input:
		MK[]: Master key
	Output:
		rk[]: round keys
	Return:
		null
	Others:
************************************************************/
func SM4_KeySchedule( MK []uint8, rk []uint32){
	// fmt.Println("SM4_KeySchedule()")

	var tmp uint32
	var buf uint32
	var K [36] uint32

	var i int

	for i = 0; i < 4; i++ {
		K[i] = SM4_FK[i] ^ ( (uint32(MK[4*i])<<24) | (uint32(MK[4*i+1])<<16) | (uint32(MK[4*i+2])<<8) | (uint32(MK[4*i+3]) ) )
	}

	for i = 0 ; i < 32 ; i++ {
		tmp = K[i+1] ^ K[i+2] ^ K[i+3] ^ SM4_CK[i]
		//nonlinear operation
		buf= uint32(SM4_Sbox[(tmp >> 24) & 0xFF]) << 24	| uint32(SM4_Sbox[(tmp >> 16) & 0xFF]) << 16| uint32(SM4_Sbox[(tmp >> 8) & 0xFF]) << 8 | uint32(SM4_Sbox[tmp & 0xFF])
		//linear operation
		K[i+4] = K[i] ^ ( (buf)^( SM4_Rotl32((buf),13) )^( SM4_Rotl32((buf),23) ) )
		rk[i] = K[i+4]
	}

	// fmt.Printf("rk=%x\n", rk)
}


/************************************************************
	Function:
		void SM4_Encrypt(unsigned char MK[],unsigned char PlainText[],unsigned char CipherText[]);
	Description:
		Encryption function
	Calls:
		SM4_KeySchedule
	Called By:
	Input:
		MK[]: Master key
		PlainText[]: input text
	Output:
		CipherText[]: output text
	Return:
		null
	Others:
************************************************************/
func SM4_Encrypt( MK []uint8, PlainText []uint8, CipherText []uint8 ) {
	// fmt.Println("SM4_Encrypt()")

	var rk [] uint32
	var X [] uint32
	var tmp uint32
	var buf uint32

	rk = make([]uint32, 32)
	X = make([]uint32, 36)

	var i, j int

	SM4_KeySchedule( MK, rk );

	for j=0 ; j<4 ; j++ {
		X[j]=(uint32(PlainText[j*4])<<24) | (uint32(PlainText[j*4+1])<<16) | (uint32(PlainText[j*4+2])<<8) | (uint32(PlainText[j*4+3]) )
	}
	for i=0;i<32;i++ {
		tmp = X[i+1]^X[i+2]^X[i+3]^rk[i];
		/* operation τ */
		buf= uint32(SM4_Sbox[(tmp >> 24) & 0xFF]) << 24	| uint32(SM4_Sbox[(tmp >> 16) & 0xFF]) << 16| uint32(SM4_Sbox[(tmp >> 8) & 0xFF]) << 8 | uint32(SM4_Sbox[tmp & 0xFF])
		/* operation L */
		X[i+4]=X[i]^(buf^SM4_Rotl32((buf),2)^ SM4_Rotl32((buf),10) ^ SM4_Rotl32((buf),18)^ SM4_Rotl32((buf),24))
	}
	for j=0;j<4;j++ {
		CipherText[4*j] = uint8((X[35-j])>> 24)& 0xFF
		CipherText[4*j+1] = uint8((X[35-j])>> 16)& 0xFF
		CipherText[4*j+2] = uint8((X[35-j])>> 8)& 0xFF
		CipherText[4*j+3] = uint8((X[35-j]))& 0xFF
	}
}

/************************************************************
	Function:
		void SM4_Decrypt(unsigned char MK[],unsigned char CipherText[], unsigned char PlainText[]);
	Description:
		Decryption function
	Calls:
		SM4_KeySchedule
	Called By:
	Input:
		MK[]: Master key
		CipherText[]: input text
	Output:
		PlainText[]: output text
	Return:
		null
	Others:
************************************************************/
func SM4_Decrypt( MK []uint8, CipherText []uint8, PlainText []uint8){
	// fmt.Println("SM4_Decrypt()")

	var rk [] uint32
	var X [] uint32
	var tmp, buf uint32

	rk = make([]uint32, 32)
	X = make([]uint32, 36)

	var i, j int
	SM4_KeySchedule( MK, rk)
	for j=0;j<4;j++	{
		X[j]=(uint32(CipherText[j*4])<<24) | (uint32(CipherText[j*4+1])<<16) | (uint32(CipherText[j*4+2])<<8) | (uint32(CipherText[j*4+3]) )
	}
	for i=0;i<32;i++ {
		tmp = X[i+1]^X[i+2]^X[i+3]^rk[31-i]
		// nonlinear operation
		/* operation τ */
		buf= uint32(SM4_Sbox[(tmp >> 24) & 0xFF]) << 24 | uint32(SM4_Sbox[(tmp >> 16) & 0xFF]) << 16| uint32(SM4_Sbox[(tmp >> 8) & 0xFF]) << 8 | uint32(SM4_Sbox[tmp & 0xFF])
		// linear operation
		/* operation L */
		X[i+4]=X[i]^(buf^SM4_Rotl32((buf),2)^ SM4_Rotl32((buf),10) ^ SM4_Rotl32((buf),18)^ SM4_Rotl32((buf),24))
	}
	for j=0;j<4;j++ {
		// 此处注意 32bit 变量位移后再进行类型转换, 否则丢失内容, 报错.
		PlainText[4*j] = uint8((X[35-j])>> 24)& 0xFF
		PlainText[4*j+1] = uint8((X[35-j])>> 16)& 0xFF
		PlainText[4*j+2] = uint8((X[35-j])>> 8)& 0xFF
		PlainText[4*j+3] = uint8((X[35-j]))& 0xFF
	}
}

/*******************************
	Function:
		SM4_Rotl32(buf, n)
	Description:
		Cycle Shift
	Calls:

	Called By:
		SM4_Decrypt
		SM4_Encrypt
	Input:
		buf uint32: Text to Shift
		n uint32: bits to shift
	Output:
		Cycle Shift Text
	Return:
		Cycle Shift Text
	Others:
**********************************/
func SM4_Rotl32(buf uint32, n uint32) uint32{
	return ( ( (buf)<<n ) | ( (buf)>>(32-n) ) )
}


/** Entrance  **/
func SM4_En(key []uint8, plain []uint8) []uint8{
	var En_output [] uint8

	En_output = make([]uint8, 16)

	SM4_Encrypt(key,plain,En_output)

	return En_output;
}

func SM4_De(key []uint8, cypher []uint8) []uint8{
	var De_output [] uint8

	De_output = make([]uint8, 16)

	SM4_Decrypt(key,cypher,De_output)

	return De_output;
}


/** Test  **/
func SM4_SelfCheck() bool{
	var i int
	//Standard data
	var key = []uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
	var plain = []uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
	var cipher = []uint8{0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46}

	fmt.Println("Plain=")
	fmt.Println(plain)
	fmt.Println("Key=")
	fmt.Println(key)
	fmt.Println("Cipher=")
	fmt.Println(cipher)

	var En_output [] uint8
	var De_output [] uint8

	En_output = make([]uint8, 16)		//切片(动态数组) 必须初始化
	De_output = make([]uint8, 16)

	SM4_Encrypt(key,plain,En_output)

	SM4_Decrypt(key,cipher,De_output)

	fmt.Println("En_output=")
	fmt.Println(En_output)
	fmt.Println("De_output=")
	fmt.Println(De_output)

	for i=0;i<16;i++ {
		if ( (En_output[i]!=cipher[i]) || (De_output[i]!=plain[i]) ){
			fmt.Println("Self-check error")
			return false
		}
	}
	fmt.Println("Self-check success")
	return true;
}


func SM4_En_CBC_Mode(PlainText []uint8, IV []uint8, Key []uint8) []uint8{
	var FormatedPlainText = PKCS5Padding_Make(PlainText)

	var CypherText = make([]uint8,0, len(FormatedPlainText))
	var TempIV = make([]uint8,0, 16)
	var TempCypherBlock = make([]uint8,16, 16)

	var i = 0
	var j = 0
	TempIV = IV

	for i = 0; i < len(FormatedPlainText)/16; i++ {
		//fmt.Printf("i=%d\n", i)
		//fmt.Printf("TempIV::%d\n", TempIV)
		//fmt.Printf("Explode Plain::")
		for j = 0; j < 16; j++ {
			//fmt.Printf("%x", FormatedPlainText[16*i + j])
			//fmt.Printf("(%x) ", TempIV[j])
			TempCypherBlock[j] = FormatedPlainText[16*i + j]^TempIV[j]
		}
		//fmt.Println("")
		//fmt.Printf("TempCypherBlock:: %x \n", TempCypherBlock)
		TempIV = SM4_En(Key, TempCypherBlock[:])
		CypherText = append(CypherText, TempIV[:]...)
	}

	return CypherText
}

func SM4_De_CBC_Mode(CypherText []uint8, IV []uint8, Key []uint8) []uint8{
	var FormatedCypherText = CypherText
	var DeCypherText = make([]uint8,0, len(FormatedCypherText))
	var TempIV = make([]uint8,0, 16)
	var TempCypherBlock = make([]uint8,16, 16)

	var i = 0
	var j = 0
	TempIV = IV

	for i = 0; i < len(FormatedCypherText)/16; i++ {
		TempCypherBlock = SM4_De(Key, FormatedCypherText[16*i : 16*i+16])

		for j = 0; j < 16; j++ {
			TempCypherBlock[j] = TempIV[j]^TempCypherBlock[j]
		}

		TempIV = FormatedCypherText[16*i : 16*i+16]

		DeCypherText = append(DeCypherText, TempCypherBlock[:]...)
	}

	return PKCS5Padding_Clear(DeCypherText)
}

func SM4_En_GCM_Mode(PlainText []uint8, IV []uint8, CTR uint32, Key []uint8, HashKey []uint8) ([]uint8, []uint8) {
	var FormatedPlainText = PKCS5Padding_Make(PlainText)

	var Len_BlockSet = len(FormatedPlainText)/16
	var Len_FormatedText = len(FormatedPlainText)

	var TempE0 = make([]uint8,0, 16)
	var TempE = make([]uint8,0, 16)
	var CypherText = make([]uint8, 0, Len_FormatedText)

	var i = 0
	var j = 0

	TempE0 = SM4_En(Key, append(IV, Uint32_to_Uint8( CTR )...) )

	for i = 0; i < Len_BlockSet; i++ {
		TempE = SM4_En(Key, append(IV, Uint32_to_Uint8( CTR+uint32(i+1) )...) )
		for j = 0; j < 16; j++ {
			TempE[j] = TempE[j]^FormatedPlainText[i*16+j]
		}
		CypherText = append(CypherText, TempE...)
	}

	// MAC
	var TempX = make([]uint8,16, 16)
	for i = 0; i < Len_BlockSet; i++ {
		for j = 0; j < 16; j++ {
			TempX[j] = TempX[j]^FormatedPlainText[i*16+j]
		}
		TempX = G_Mul_128( TempX, HashKey )
	}
	for i = 0; i < Len_BlockSet; i++ {
		for j = 0; j < 16; j++ {
			TempX[j] = TempX[j]^CypherText[i*16+j]
		}
		TempX = G_Mul_128( TempX, HashKey )
	}

	var Bit_Len_PlainText = uint32( len(PlainText)*8 )
	var Bit_Len_CypherText = uint32( len(CypherText)*8 )
	var Null = make([]uint8, 4, 4)
	var Len = make([]uint8, 0, 16)
	Len = append(Len, Null...)
	Len = append(Len, Uint32_to_Uint8(Bit_Len_PlainText)...)
	Len = append(Len, Null...)
	Len = append(Len, Uint32_to_Uint8(Bit_Len_CypherText)...)

	for j = 0; j < 16; j++ {
			TempX[j] = TempX[j]^Len[j]
	}
	TempX = G_Mul_128( TempX, HashKey )

	for j = 0; j < 16; j++ {
			TempX[j] = TempX[j]^TempE0[j]
	}

	return CypherText, TempX
}

func SM4_De_GCM_Mode(CypherText []uint8, IV []uint8, CTR uint32, Key []uint8, HashKey []uint8, MAC []uint8) []uint8{

	var Len_BlockSet = len(CypherText)/16
	var Len_FormatedText = len(CypherText)

	var TempE0 = make([]uint8,0, 16)
	TempE0 = SM4_En(Key, append(IV, Uint32_to_Uint8( CTR )...) )
	var TempE = make([]uint8,0, 16)
	var FormatedPlainText = make([]uint8, 0, Len_FormatedText)

	var i = 0
	var j = 0

	for i = 0; i < Len_BlockSet; i++ {
		TempE = SM4_En(Key, append(IV, Uint32_to_Uint8( CTR+uint32(i+1) )...) )
		for j = 0; j < 16; j++ {
			TempE[j] = TempE[j]^CypherText[i*16+j]
		}
		FormatedPlainText = append(FormatedPlainText, TempE...)
	}

	// check MAC
	var TempX = make([]uint8,16, 16)
	for i = 0; i < Len_BlockSet; i++ {
		for j = 0; j < 16; j++ {
			TempX[j] = TempX[j]^FormatedPlainText[i*16+j]
		}
		TempX = G_Mul_128( TempX, HashKey )
	}
	for i = 0; i < Len_BlockSet; i++ {
		for j = 0; j < 16; j++ {
			TempX[j] = TempX[j]^CypherText[i*16+j]
		}
		TempX = G_Mul_128( TempX, HashKey )
	}

	var Bit_Len_PlainText = uint32( len( PKCS5Padding_Clear(FormatedPlainText) )*8 )
	var Bit_Len_CypherText = uint32( len(CypherText)*8 )
	var Null = make([]uint8, 4, 4)
	var Len = make([]uint8, 0, 16)
	Len = append(Len, Null...)
	Len = append(Len, Uint32_to_Uint8(Bit_Len_PlainText)...)
	Len = append(Len, Null...)
	Len = append(Len, Uint32_to_Uint8(Bit_Len_CypherText)...)

	for j = 0; j < 16; j++ {
			TempX[j] = TempX[j]^Len[j]
	}
	TempX = G_Mul_128( TempX, HashKey )

	for j = 0; j < 16; j++ {
			TempX[j] = TempX[j]^TempE0[j]
	}

	for j = 0; j < 16; j++ {
		if TempX[j]!=MAC[j] {
			fmt.Printf("MAC check failed:: %x \n", TempX)
			return nil
		}
	}

	return PKCS5Padding_Clear(FormatedPlainText)
}

/* make a string to blocks */
func PKCS5Padding_Make(OriginText []uint8) []uint8{

	var textLength = uint32( len(OriginText) )
	var appendixLength = uint8(16 - textLength%16)

	var appendix = make([]uint8, appendixLength)
	var i uint8 = 0
	for ; i < appendixLength; i++ {
		appendix[i] = appendixLength
	}

	var formatedText = make([]uint8, 0, textLength + uint32(appendixLength))

	formatedText = append(OriginText[:], appendix[:]...)
	return formatedText
}

/* make a string from blocks to origin */
func PKCS5Padding_Clear(PaddingText []uint8) []uint8{
	
	var Flag = int( PaddingText[len(PaddingText)-1] )
	return PaddingText[:len(PaddingText)-Flag]
}

/* turn CTR(uint32) to CTR(uint8*4) */
func Uint32_to_Uint8(CTR uint32) []uint8{
	var Temp = make([]uint8, 4, 4)
	/*
	Temp[0] = uint8( (0xff000000 & CTR)>>24 );
	Temp[1] = uint8( (0x00ff0000 & CTR)>>16 );
	Temp[2] = uint8( (0x0000ff00 & CTR)>>8 );
	Temp[3] = uint8( 0x000000ff & CTR );
	*/
	Temp[0] = uint8( CTR>>24 );
	Temp[1] = uint8( CTR>>16 );
	Temp[2] = uint8( CTR>>8 );
	Temp[3] = uint8( CTR );

	return Temp;
}

/* Galois Field Multiply (128bit) */
func G_Mul_128(x []uint8, y []uint8) []uint8 {
	GeneraterElement_128 := new(big.Int)
	GeneraterElement_128.SetString("100000000000000000000000000000087", 16) // x^128+x^7+x^2+x^1+X^0

	X := new(big.Int)
	Y := new(big.Int)
	X.SetString( Uint8_to_String(x), 16) // Big type
	Y.SetString( Uint8_to_String(y), 16) 

	Z := new(big.Int)
	Z.SetString( "1", 16)

	T := new(big.Int)

	Mul_Result := new(big.Int)
	Mul_Result.SetString( "0", 16)

	Nonce_Big := new(big.Int)
	Nonce_Big.SetString( "0", 16)

	// Mul
	var i uint = 0
	for ; i < 128; i++ {
		Nonce_Big.Set(Z)

		T.Set( Nonce_Big.And(Nonce_Big, Y) )

		if T.Sign()!=0 {

			Nonce_Big.Set(X)

			Nonce_Big = Nonce_Big.Mul(Nonce_Big, T)

			Mul_Result = Mul_Result.Xor( Mul_Result, Nonce_Big )
		}

		Z = Z.Lsh(Z,1)
	}

	// Mod
	var L =  uint( Mul_Result.BitLen() )
	Z.SetString( "1", 16)
	if L==0 {
		Z.SetString( "0", 16)
	}else{
		Z = Z.Lsh(Z,(L-1))
	}

	for i = L ; i > 0; i-- {
		if i<=128 {
			break
		}

		Nonce_Big.Set(Z)
		Nonce_Big = Nonce_Big.And(Nonce_Big, Mul_Result) 
		Nonce_Big.Set( Nonce_Big.And(Nonce_Big, Mul_Result) )

		if Nonce_Big.Sign()!=0 {
			Nonce_Big.Set(GeneraterElement_128)

			Nonce_Big = Nonce_Big.Lsh(Nonce_Big, i-128-1 )

			Mul_Result = Mul_Result.Xor( Mul_Result, Nonce_Big )
		}

		Z = Z.Rsh(Z,1)
	}
	RRR := Mul_Result.Bytes()
	if len(RRR)<16 {
		var ZeroPadding = make([]uint8, 16-len(RRR), 16-len(RRR))
		RRR = append(ZeroPadding, RRR[:]...)
	}

	return RRR
}

func Uint8_to_String(X []uint8) string{
	s := ""
	i :=0
	L := len(X)
	for ; i < L; i++ {
		s += strconv.FormatInt(int64(X[i]), 16)
	}
	return s	
}
