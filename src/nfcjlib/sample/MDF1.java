package nfcjlib.sample;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV1.KeyType;
import nfcjlib.core.util.Dump;

/**
 * Sample application with a value file using a MIFARE DESFire EV1.
 * <p>
 * Format the PICC. Create an application with the chosen cipher,
 * three value files, increase the stored values and retrieve those
 * values from the card. There is one value file created for each of the
 * possible communication settings (plain=0, maced=1, enciphered=3).
 * <p>
 * The card is assumed to have the PICC master key set to AES with
 * all 16 bytes cleared.
 * 
 * @author	Daniel Andrade
 * @version	9.9.2013, 0.4
 */
class MDF1 {

	public static void main(String[] args) {

		// Choose the application cipher type here: DES, 3K3DES or AES.
		// Note: does not work with 3DES (would require a change key).
		runSample(KeyType.TKTDES);

	}

	private static void runSample(KeyType applicationCipherType) {
		byte[] skey, appKey, aid, payload;
		byte amks, nok, fileNo1, fileNo2, fileNo3, cs, ar1, ar2;
		Integer val;
		DESFireEV1 desfire = new DESFireEV1();

		// establish a connection with the card
		if (!desfire.connect())
			return;

		// authenticate with PICC master key (AES, 16 bytes cleared)
		skey = desfire.authenticate(new byte[16], (byte) 0x00, KeyType.AES);
		if (skey == null) {
			System.out.println("Session key is null");
			return;
		}
		System.out.println("The secret  key is " + Dump.hex(new byte[16]));
		System.out.println("The session key is " + Dump.hex(skey));

		// format PICC
		if (!desfire.formatPICC())
			return;

		// create an application
		aid = new byte[] {0x01, 0x02, 0x03};
		amks = 0x0F;
		switch (applicationCipherType) {
		case DES:
			nok = 0x05;
			appKey = new byte[8];
			break;
		case TKTDES:
			nok = 0x45;
			appKey = new byte[24];
			break;
		case AES:
			nok = (byte) 0x85;
			appKey = new byte[16];
			break;
		default:
			return;
		}
		if (!desfire.createApplication(aid, amks, nok))
			return;

		// select the application created
		if(!desfire.selectApplication(aid))
			return;

		// authenticate with the 3rd application key (default one)
		// (RW is set to 0x3: grants access to credit/getValue operations)
		skey = desfire.authenticate(appKey, (byte) 0x03, applicationCipherType);
		if (skey == null) {
			System.out.println("Session key is null (application)");
			return;
		}
		System.out.println("The secret  key is " + Dump.hex(appKey));
		System.out.println("The session key is " + Dump.hex(skey));

		// create a value file in the new application: fileNo=4, cs=0
		fileNo1 = 0x04;
		cs = 0x00;
		ar1 = 0x30;  // RW|CAR
		ar2 = 0x00;  // R|W
		payload = new byte[] {
				fileNo1, cs, ar1, ar2,
				10, 0, 0, 0,  // lower limit: 10
				90, 0, 0, 0,  // upper limit: 90
				50, 0, 0, 0,  // initial value: 50
				0  // limitedCredit operation disabled
		};
		if (!desfire.createValueFile(payload))
			return;

		// create a value file in the new application: fileNo=5, cs=1
		fileNo2 = 0x05;
		cs = 0x01;
		ar1 = 0x30;  // RW|CAR
		ar2 = 0x00;  // R|W
		payload = new byte[] {
				fileNo2, cs, ar1, ar2,
				10, 0, 0, 0,  // lower limit: 10
				90, 0, 0, 0,  // upper limit: 90
				50, 0, 0, 0,  // initial value: 50
				0  // limitedCredit operation disabled
		};
		if (!desfire.createValueFile(payload))
			return;

		// create a value file in the new application: fileNo=6, cs=3
		fileNo3 = 0x06;
		cs = 0x03;
		ar1 = 0x30;  // RW|CAR
		ar2 = 0x00;  // R|W
		payload = new byte[] {
				fileNo3, cs, ar1, ar2,
				10, 0, 0, 0,  // lower limit: 10
				90, 0, 0, 0,  // upper limit: 90
				50, 0, 0, 0,  // initial value: 50
				0  // limitedCredit operation disabled
		};
		if (!desfire.createValueFile(payload))
			return;


		// increase the value stored in the last value file (twice!):
		// - requires preceding authentication with RW key (done); and a
		// - commit transaction after the credit operation
		if (!desfire.credit(fileNo1, 7))
			return;
		if (!desfire.credit(fileNo1, 7))
			return;
		if (!desfire.commitTransaction())
			return;
		if (!desfire.credit(fileNo2, 7))
			return;
		if (!desfire.credit(fileNo2, 7))
			return;
		if (!desfire.commitTransaction())
			return;
		if (!desfire.credit(fileNo3, 7))
			return;
		if (!desfire.credit(fileNo3, 7))
			return;
		if (!desfire.commitTransaction())
			return;

		// read the stored value ( = initial value + credit + credit )
		val = desfire.getValue(fileNo1);
		if (val == null)
			return;
		System.out.println("The stored value (fileNo=4, cs=0) is " + val.intValue());
		val = desfire.getValue(fileNo2);
		if (val == null)
			return;
		System.out.println("The stored value (fileNo=5, cs=1) is " + val.intValue());
		val = desfire.getValue(fileNo3);
		if (val == null)
			return;
		System.out.println("The stored value (fileNo=6, cs=3) is " + val.intValue());

		// tear down the connection with the card
		if (!desfire.disconnect())
			return;

		System.out.println("success.");
	}

}