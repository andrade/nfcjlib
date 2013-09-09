package nfcjlib.sample;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV1.KeyType;
import nfcjlib.core.util.Dump;

/**
 * Usage example of the library.
 * 
 * @author	Daniel Andrade
 * @version	9.9.2013, 0.4
 */
public class Example1 {

	public static void main(String[] args) {
		byte[] aid = new byte[] {0x09, 0x09, 0x09};
		byte fid = 0x01, cs = 0x00, ar1 = 0x33, ar2 = 0x33;
		DESFireEV1 desfire = new DESFireEV1();

		desfire.connect();

		// select PICC-level, authenticate, format card
		desfire.selectApplication(new byte[] {0x00, 0x00, 0x00});
		desfire.authenticate(new byte[16], (byte) 0x00, KeyType.AES);
		desfire.formatPICC();

		// create and select an application
		desfire.createApplication(aid, (byte) 0x0F, (byte) 0x85);
		desfire.selectApplication(aid);

		// create a standard data file and authenticate with key 0x03
		desfire.createStdDataFile(new byte[] {fid, cs, ar1, ar2, 0x40, 0x00, 0x00});
		desfire.authenticate(new byte[16], (byte) 0x03, KeyType.AES);

		// write into and read from the file
		desfire.writeData(new byte[] {
				fid, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
				0x1a, 0x2b, 0x3c, 0x4d, 0x5e
		});
		byte[] ret = desfire.readData(new byte[] {
				fid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		});
		if (ret != null)
			System.out.println("Read: " + Dump.hex(ret));

		desfire.disconnect();
	}

}