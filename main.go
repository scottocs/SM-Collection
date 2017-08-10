/* Written by ZL, CZN, GJX from Fudan University */
package main

import (
	"fmt"
	"reflect"
	"SM/SM4"
	"SM/SM3"
	"SM/SM2"
)

func main() {

	/******  SM4  ******/
	fmt.Println("******************************************************************")
	fmt.Println("<SM4>")

	var key = []uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
	var plain = []uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
	
	fmt.Printf("\n@Encrypt\n")
	var CypherText =  SM4.SM4_En( key, plain)
	fmt.Printf("key:: %x\n",key)
	fmt.Printf("plain:: %x\n",plain)
	fmt.Printf("CypherText:: %x\n",CypherText)

	fmt.Printf("\n@Decrypt\n")
	var OriginText =  SM4.SM4_De( key, CypherText)
	fmt.Printf("OriginText:: %x\n",OriginText)

	fmt.Println("<SM4/>")
	fmt.Println("******************************************************************")


	/******  SM3  ******/
	fmt.Println("******************************************************************")
	fmt.Println("<SM3>")

	var Msg  = [] uint8 {0x61,0x62,0x63}

	fmt.Printf("\n@Hash\n")
	var Hash =  SM3.SM3_To_256( Msg )

	fmt.Printf("Msg:: %x\n",Msg)
	fmt.Printf("Hash:: %x\n",Hash)

	fmt.Println("<SM3/>")
	fmt.Println("******************************************************************")

	/******  SM2 Encrypt&Decrypt  ******/
	fmt.Println("******************************************************************")
	fmt.Println("<SM2_EnDe>")

	var PriKey = []uint8{0x16,0x49,0xAB,0x77,0xA0,0x06,0x37,0xBD,0x5E,0x2E,0xFE,0x28,0x3F,0xBF,0x35,0x35,0x34,0xAA,0x7F,0x7C,0xB8,0x94,0x63,0xF2,0x08,0xDD,0xBC,0x29,0x20,0xBB,0x0D,0xA0}
	var SM2_Msg  = []uint8{0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64}

	fmt.Printf("\n@Encrypt\n")
	CyperText, Err :=  SM2.SM2_En(PriKey, SM2_Msg)
	fmt.Printf("SM2_Msg:: %x\n",SM2_Msg)
	fmt.Printf("CyperText::%x\n",CyperText)

	fmt.Printf("\n@Decrypt\n")
	SM2_OriginText, Err :=  SM2.SM2_De(PriKey, CyperText)
	fmt.Printf("SM2_OriginText::%x\n",SM2_OriginText)
	fmt.Printf("Err::%x\n",Err)	

	fmt.Println("<SM2_EnDe/>")
	fmt.Println("******************************************************************")

	/******  SM2 Singature  ******/
	fmt.Println("******************************************************************")
	fmt.Println("<SM2_Singature>")

	var SM2_Sig_PriKey = []uint8{0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8}
	var IDA = []uint8{0x42, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33, 0x40, 0x59, 0x41,0x48, 0x4F, 0x4F, 0x2E, 0x43, 0x4F,0x11} //ASCII code of userA's identification
	var SM2_Sig_Msg string = "message digest"

	fmt.Printf("\n@Signature\n")
	R, S, PubKey, Err :=  SM2.SM2_Si(SM2_Sig_PriKey, IDA, []uint8(SM2_Sig_Msg))
	fmt.Printf("SM2_Sig_PriKey:: %x\n",SM2_Sig_PriKey)
	fmt.Printf("IDA:: %x\n",IDA)
	fmt.Printf("SM2_Sig_Msg(String):: %v\n",SM2_Sig_Msg)
	fmt.Printf("R::%x\n",R)
	fmt.Printf("S::%x\n",S)
	fmt.Printf("Err::%x\n",Err)

	fmt.Printf("\n@Verify\n")
	VerifyResult, Err :=  SM2.SM2_Ve(PubKey, IDA, []uint8(Msg), R, S)
	fmt.Printf("VerifyResult::%v\n",VerifyResult)
	fmt.Printf("Err::%x\n",Err)

	fmt.Println("<SM2_Singature/>")
	fmt.Println("******************************************************************")


	/******  SM2 KeyExchange  ******/
	fmt.Println("******************************************************************")
	fmt.Println("<SM2_KeyExchange>\n")

	/* 2 guys all have this argument */
	fmt.Printf("\n@2 guys all have this argument\n")
	var Requester__PriKey = []uint8{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1, 0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52, 0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1, 0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	var Responser__PriKey = []uint8{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA, 0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38, 0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88, 0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	
	var Requester__ID = []uint8{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	var Responser__ID = []uint8{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

	Requester__Z, err := SM2.SM2_Gen_Z(Requester__ID, Requester__PriKey)
	Responser__Z, err := SM2.SM2_Gen_Z(Responser__ID, Responser__PriKey)

	var K = []uint8{0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84, 0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5}
	var Klen int = len(K)*8

	fmt.Printf("K::%x\n",K)
	fmt.Printf("Klen::%x\n",Klen)
	fmt.Printf("Requester__Z::%x\n",Requester__Z)
	fmt.Printf("Responser__Z::%x\n",Responser__Z)
	fmt.Printf("err::%x\n",err)

	/********** Step 1 *********/
	// Reuqester generates PubKey
	fmt.Printf("\n@Reuqester generates PubKey\n")
	Requester__PubKey, err := SM2.SM2_GetPubKey(Requester__PriKey)

	fmt.Printf("Requester__PubKey::%x\n",Requester__PubKey)
	fmt.Printf("err::%x\n",err)

	// Reuqester generates r and R	
	fmt.Printf("\n@Reuqester generates r and R\n")
	Requester__r := SM2.Cal_r()  //type Big

	// Reuqester makes r to string type, so r can be sent
	fmt.Printf("\n@Reuqester makes r to string type, so r can be sent\n")
	var Requester__r_string = make([]uint8, 32)
	SM2.Big_to_bytes(32, Requester__r, Requester__r_string[0 : 32], true)

	fmt.Printf("Requester__r_string::%x\n",Requester__r_string)

	/********** Reuqester Send R to Responser ***********/
	/********** run: send(Requester__Rstring) ***********/

	/********** Step 2 ***********/
	// Responser generates PubKey
	fmt.Printf("\n@Responser generates PubKey\n")
	Responser__PubKey, err := SM2.SM2_GetPubKey(Responser__PriKey)

	fmt.Printf("Responser__PubKey::%x\n",Responser__PubKey)
	fmt.Printf("err::%x\n",err)

	// Responser gets Requester's r(string), parses to type Big
	fmt.Printf("\n@Responser gets Requester's r(string), parses to type Big\n")
	var _Requester__r SM2.Big
	_Requester__r = SM2.Mirvar(0)
	SM2.Bytes_to_big(32, Requester__r_string[0:32], _Requester__r)
	var _Requester__R *SM2.Epoint
	_Requester__R = SM2.Epoint_init()
	SM2.SM2_KeyGeneration(_Requester__r, _Requester__R)

	// Responser generates R, S02, S03
	// (S02=Hash(0x02||yV||Hash(xV||ZA||ZB||x1||y1||x2||y2)))
	fmt.Printf("\n@Responser generates R, S02, S03\n")
	Responser__r, Responser__S02, Responser__S03, Responser__K, err := SM2.Responser__Get_R_S02_S03(Responser__PriKey, _Requester__R, Requester__PubKey, Requester__Z, Responser__Z, Klen)
	fmt.Printf("Responser__S02::%x\n",Responser__S02)
	fmt.Printf("Responser__S03::%x\n",Responser__S03)
	fmt.Printf("Responser__K::%x\n",Responser__K)
	fmt.Printf("err::%x\n",err)

	// Responser checks Requester's R
	fmt.Printf("\n@Responser checks Requester's R\n")
	Responser__RCheckResult := SM2.CheckR(_Requester__R)
	if !Responser__RCheckResult {
		// Check failed
		// do something
		fmt.Printf("Check failed::Responser checks Requester's R\n")
	}

	// Responser makes r to string type, so r can be sent
	fmt.Printf("Responser makes r to string type, so r can be sent\n")
	var Responser__r_string = make([]uint8, 32)
	SM2.Big_to_bytes(32, Responser__r, Responser__r_string[0 : 32], true)
	fmt.Printf("Responser__r_string::%x\n",Responser__r_string)

	/********** Responser Send r, S02 to Requester ***********/
	/********** run: send(Responser__r_string) ***********/
	/********** run: send(Responser__S02) ***********/

	/********** Step 3 ***********/
	// Requester gets Responser's r(string),S02(string), parses r to type *Epoint
	fmt.Printf("Requester gets Responser's r(string),S02(string), parses r to type *Epoint\n")
	var _Responser__r SM2.Big
	_Responser__r = SM2.Mirvar(0)
	SM2.Bytes_to_big(32, Responser__r_string[0:32], _Responser__r)
	var _Responser__R *SM2.Epoint
	_Responser__R = SM2.Epoint_init()
	SM2.SM2_KeyGeneration(_Responser__r, _Responser__R)

	// Requester generates S02, S03
	// (S02=Hash(0x02||yV||Hash(xV||ZA||ZB||x1||y1||x2||y2)))
	fmt.Printf("Requester generates R, S02, S03\n")
	Klen = 128 //2 guys all have this argument

	Requester__S02, Requester__S03, Requester__K, err := SM2.Requester__Get_S02_S03(Requester__PriKey, Requester__r, _Responser__R, Responser__PubKey, Requester__Z, Responser__Z, Klen)
	fmt.Printf("Requester__S02::%x\n",Requester__S02)
	fmt.Printf("Requester__S03::%x\n",Requester__S03)
	fmt.Printf("Requester__K::%x\n",Requester__K)
	fmt.Printf("err::%x\n",err)

	// Requester checks Responser's R
	fmt.Printf("Requester checks Responser's R\n")
	Requester__RCheckResult := SM2.CheckR(_Responser__R)
	if !Requester__RCheckResult {
		// Check failed
		// do something
		fmt.Printf("Check failed::Requester checks Responser's R\n")
	}

	// Requester checks Responser's S02
	fmt.Printf("Requester checks Responser's S02\n")
	if !reflect.DeepEqual( Requester__S02, Responser__S02 ) {
		// Check failed
		// do something
		fmt.Printf("Check failed::Requester checks Responser's S02\n")
	}

	/********** Reuqester Send S03 to Responser ***********/
	/********** run: send(Requester__S03) ***********/

	/********** Step 4 ***********/
	// Responser checks Reuqester's S03
	fmt.Printf("Responser checks Reuqester's S03\n")

	if !reflect.DeepEqual( Requester__S03, Responser__S03 ) {
		// Check failed
		// do something
		fmt.Printf("Check failed::Responser checks Reuqester's S03\n")
	}

	/********** Step 5 ***********/
	// if no error occured, Negotiation is successful

	fmt.Printf("no error occured, Negotiation is successful\n")

	fmt.Println("\n</SM2_KeyExchange>")
	fmt.Println("******************************************************************")

	return
}
