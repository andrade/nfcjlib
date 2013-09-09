package nfcjlib.sample;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV1.KeyType;
import nfcjlib.core.util.Dump;

/**
 * @author Daniel Andrade
 */
public class ExampleCreate {
	
	private static final byte[] APPLICATION_ID = new byte[] {0x05, 0x06, 0x07};

	public static void main(String[] args) {
		DESFireEV1 desfire = new DESFireEV1();
		
		// connect to card
		desfire.connect();
		
		// select PICC (is selected by default but...)
		desfire.selectApplication(new byte[] {0x00, 0x00, 0x00});
		
		// authenticate: assume default key with cipher AES
		desfire.authenticate(new byte[16], (byte) 0x00, KeyType.AES);
		
		
		// create application (0x42 means 3K3DES cipher and two application keys)
		desfire.createApplication(APPLICATION_ID, (byte) 0x0F, (byte) 0x42);
		
		// select application
		desfire.selectApplication(APPLICATION_ID);
		
		// authenticate inside application with key 0x00 and cipher 3K3DES
		desfire.authenticate(new byte[24], (byte) 0x00, KeyType.TKTDES);
		
		// get files IDs (none found because none were created)
		byte[] ret = desfire.getFileIds();
		if (ret == null)
			System.out.println("File IDs returned null");
		else
			System.out.println("File IDs returned: " + Dump.hex(ret));
		
		// disconnect from card
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
<< cd d4 7e ed e6 8a 9d a8 3b 06 2d a9 8f 1b d4 87 91 af (ADDITIONAL_FRAME)
>> 90 af 00 00 20 c2 d4 48 ab 0f c0 50 a0 15 fd 1b bc 18 31 c5 00 6d 8f f5 8d 7c 44 30 2b 38 1f d2 e6 8e ee 1b 45 00 (MORE)
<< 5d d2 a1 08 eb 34 d3 73 9b d7 1d ed 69 6a 75 48 91 00 (OPERATION_OK)
>> 90 ca 00 00 05 05 06 07 0f 42 00 (CREATE_APPLICATION)
<< c2 20 61 c1 77 0a 96 6c 91 00 (OPERATION_OK)
>> 90 5a 00 00 03 05 06 07 00 (SELECT_APPLICATION)
<< 91 00 (OPERATION_OK)
>> 90 1a 00 00 01 00 00 (AUTHENTICATE_3K3DES)
<< 4c 00 46 89 a9 d0 00 db a9 86 5a 5e 4d 82 e5 8a 91 af (ADDITIONAL_FRAME)
>> 90 af 00 00 20 67 46 58 37 85 fe cb 51 8f 1a 90 d7 d1 88 37 bb 06 52 2c dd bf 96 a8 63 d4 d4 7f c0 20 96 62 5b 00 (MORE)
<< 43 99 51 17 98 b8 03 72 cc 89 77 a3 18 67 5a b9 91 00 (OPERATION_OK)
>> 90 6f 00 00 00 (GET_FILE_IDS)
<< 16 49 ea d0 f0 6e 23 91 91 00 (OPERATION_OK)
File IDs returned:
 * 
 */