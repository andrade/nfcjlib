package nfcjlib.sample;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV1.KeyType;
import nfcjlib.core.util.Dump;

/**
 * @author Daniel Andrade
 */
public class ExampleAuth {

	public static void main(String[] args) {
		DESFireEV1 desfire = new DESFireEV1();
		desfire.connect();
		
		// select PICC (is selected by default but...)
		desfire.selectApplication(new byte[] {0x00, 0x00, 0x00});
		
		// authenticate: assume default key with cipher AES
		byte[] sessionKey = desfire.authenticate(new byte[16], (byte) 0x00, KeyType.AES);
		System.out.println("Session key is " + Dump.hex(sessionKey));
		
		desfire.disconnect();
	}

}
/* 
 * EXAMPLE OUTPUT:
 * 
PC/SC card in SCL011G Contactless Reader [SCL01x Contactless Reader] (21161044200765) 00 00, protocol T=1, state OK
>> 90 5a 00 00 03 00 00 00 00 (SELECT_APPLICATION)
<< 91 00 (OPERATION_OK)
>> 90 aa 00 00 01 00 00 (AUTHENTICATE_AES)
<< cc 11 3e 08 27 7a a4 0e 04 19 47 e4 6e f9 f4 cd 91 af (ADDITIONAL_FRAME)
>> 90 af 00 00 20 13 33 d8 c8 15 1a f1 d3 f5 71 b2 dd c1 4f ad 1c 32 c4 18 b1 db 14 35 8a 4f 14 3e c9 bc d9 db f2 00 (MORE)
<< c7 6d 8b 1e 84 1b b7 56 9a fa 40 b0 81 da 8c 69 91 00 (OPERATION_OK)
The random A is e2 b1 e6 6b d5 81 70 37 79 2d 47 72 6d b5 a2 1a
The random B is e4 52 67 6a 81 f3 7b 7b 7e 23 25 28 5c 71 f8 1b
Session key is e2 b1 e6 6b e4 52 67 6a 6d b5 a2 1a 5c 71 f8 1b
 * 
 */
