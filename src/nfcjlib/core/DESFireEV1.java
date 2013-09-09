/* ****************************************
 * Copyright (c) 2013, Daniel Andrade
 * All rights reserved.
 * 
 * (1) Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. (2) Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution. (3) The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * Modified BSD License (3-clause BSD)
 */
package nfcjlib.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import nfcjlib.core.util.AES;
import nfcjlib.core.util.BitOp;
import nfcjlib.core.util.CMAC;
import nfcjlib.core.util.CRC16;
import nfcjlib.core.util.CRC32;
import nfcjlib.core.util.Dump;
import nfcjlib.core.util.TripleDES;

/**
 * Enables a client to interact with a MIFARE DESFire EV1 smart card.
 * Not all 35 commands are implemented.
 * Developed and tested using an MDF version 1.4.
 * 
 * @author	Daniel Andrade
 * @version	9.9.2013, 0.4
 */
public class DESFireEV1 extends SimpleSCR {
	
	/** A file/key number that does not exist. */
	private final static byte FAKE_NO = -1;

	private KeyType ktype;    // type of key used for authentication
	private byte kno;         // keyNo used for successful authentication
	private byte[] aid;       // currently selected 3-byte AID
	private byte[] iv;        // the IV, kept updated between operations (for 3K3DES/AES)
	private byte[] skey;      // session key: set on successful authentication

	private byte fileNo;      // file number of the last used file (caching)
	private byte[] fileSett;  // file settings of the last used file (caching)

	private int code;         // response status code of previous command

	public DESFireEV1() {
		reset();
		aid = new byte[3];
	}

	@Override
	public boolean disconnect() {
		reset();
		return super.disconnect();
	}

	/**
	 * Reset the attributes of this instance to their default values.
	 * Called when the authentication status is changed, such as after a
	 * change key or AID selection operation.
	 */
	private void reset() {
		ktype = null;
		kno = FAKE_NO;
		//aid = new byte[3];  // authentication resets but AID does not change.
		iv = null;
		skey = null;

		fileNo = FAKE_NO;
		fileSett = null;
	}

	/**
	 * Mutual authentication between PCD and PICC.
	 * 
	 * @param key	the secret key (8 bytes for DES, 16 bytes for 3DES/AES and
	 * 				24 bytes for 3K3DES)
	 * @param keyNo	the key number
	 * @param type	the cipher
	 * @return		the session key on success, <code>null</code> otherwise
	 */
	public byte[] authenticate(byte[] key, byte keyNo, KeyType type) {
		if (!validateKey(key, type))
			return null;
		if (type != KeyType.AES) {
			// remove version bits from Triple DES keys
			setKeyVersion(key, 0, key.length, (byte) 0x00);
		}

		final byte[] iv0 = type == KeyType.AES ? new byte[16] : new byte[8];
		byte[] apdu;
		CommandAPDU command;
		ResponseAPDU response;

		// 1st message exchange
		apdu = new byte[7];
		apdu[0] = (byte) 0x90;
		switch (type) {
		case DES:
		case TDES:
			apdu[1] = (byte) Command.AUTHENTICATE_DES_2K3DES.getCode();
			break;
		case TKTDES:
			apdu[1] = (byte) Command.AUTHENTICATE_3K3DES.getCode();
			break;
		case AES:
			apdu[1] = (byte) Command.AUTHENTICATE_AES.getCode();
			break;
		default:
			assert false : type;
		}
		apdu[4] = 0x01;
		apdu[5] = keyNo;
		command = new CommandAPDU(apdu);
		response = transmit(command);
		this.code = response.getSW2();
		feedback(command, response);
		if (response.getSW2() != 0xAF)
			return null;

		// step 3
		byte[] randB = recv(key, response.getData(), type, iv0);
		if (randB == null)
			return null;
		byte[] randBr = rotateLeft(randB);
		byte[] randA = new byte[randB.length];
		SecureRandom g = new SecureRandom();
		g.nextBytes(randA);

		// step 3: encryption
		byte[] plaintext = new byte[randA.length + randBr.length];
		System.arraycopy(randA, 0, plaintext, 0, randA.length);
		System.arraycopy(randBr, 0, plaintext, randA.length, randBr.length);
		byte[] iv1 = Arrays.copyOfRange(response.getData(),
				response.getData().length - iv0.length, response.getData().length);
		byte[] ciphertext = send(key, plaintext, type, iv1);
		if (ciphertext == null)
			return null;

		// 2nd message exchange
		apdu = new byte[5 + ciphertext.length + 1];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) 0xAF;
		apdu[4] = (byte) ciphertext.length;	
		System.arraycopy(ciphertext, 0, apdu, 5, ciphertext.length);
		command = new CommandAPDU(apdu);
		response = transmit(command);
		this.code = response.getSW2();
		feedback(command, response);
		if (response.getSW2() != 0x00)
			return null;

		// step 5
		byte[] iv2 = Arrays.copyOfRange(ciphertext,
				ciphertext.length - iv0.length, ciphertext.length);
		byte[] randAr = recv(key, response.getData(), type, iv2);
		if (randAr == null)
			return null;
		byte[] randAr2 = rotateLeft(randA);
		for (int i = 0; i < randAr2.length; i++)
			if (randAr[i] != randAr2[i])
				return null;

		// step 6
		byte[] skey = generateSessionKey(randA, randB, type);
		System.out.println("The random A is " + Dump.hex(randA));
		System.out.println("The random B is " + Dump.hex(randB));

		this.ktype = type;
		this.kno = keyNo;
		this.iv = iv0;
		this.skey = skey;

		return skey;
	}

	/**
	 * Generate the session key using the random A generated by the PICC and
	 * the random B generated by the PCD.
	 * 
	 * @param randA	the random number A
	 * @param randB	the random number B
	 * @param type	the type of key
	 * @return		the session key
	 */
	private static byte[] generateSessionKey(byte[] randA, byte[] randB, KeyType type) {
		byte[] skey = null;

		switch (type) {
		case DES:
			skey = new byte[8];
			System.arraycopy(randA, 0, skey, 0, 4);
			System.arraycopy(randB, 0, skey, 4, 4);
			break;
		case TDES:
			skey = new byte[16];
			System.arraycopy(randA, 0, skey, 0, 4);
			System.arraycopy(randB, 0, skey, 4, 4);
			System.arraycopy(randA, 4, skey, 8, 4);
			System.arraycopy(randB, 4, skey, 12, 4);
			break;
		case TKTDES:
			skey = new byte[24];
			System.arraycopy(randA, 0, skey, 0, 4);
			System.arraycopy(randB, 0, skey, 4, 4);
			System.arraycopy(randA, 6, skey, 8, 4);
			System.arraycopy(randB, 6, skey, 12, 4);
			System.arraycopy(randA, 12, skey, 16, 4);
			System.arraycopy(randB, 12, skey, 20, 4);
			break;
		case AES:
			skey = new byte[16];
			System.arraycopy(randA, 0, skey, 0, 4);
			System.arraycopy(randB, 0, skey, 4, 4);
			System.arraycopy(randA, 12, skey, 8, 4);
			System.arraycopy(randB, 12, skey, 12, 4);
			break;
		default:
			assert false : type;  // never reached
		}

		return skey;
	}

	/**
	 * Change the master key settings or the application master key settings,
	 * depending on the selected AID.
	 * <p>
	 * Requires a preceding authentication.
	 * 
	 * @param keySett	the new key settings
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean changeKeySettings(byte keySett) {
		byte[] apdu = new byte[7];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.CHANGE_KEY_SETTINGS.getCode();
		apdu[4] = 0x01;
		apdu[5] = keySett;

		apdu = preprocess(apdu, CommunicationSetting.ENCIPHERED);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	//TODO setConfiguration

	/**
	 * Change any key stored on the PICC. The version will be set to zero.
	 * 
	 * @param keyNo		the number of the key to be changed
	 * @param newType	the type of the new key
	 * @param newKey	the new key (8-bytes for DES,
	 * 					16-bytes for 2K3DES/AES, 24-bytes 3K3DES)
	 * @param oldKey	the old key (only required if the the key being
	 * 					changed is different from the authenticated key; can be
	 * 					set to <code>null</code> if both keys are the same)
	 * @return			the APDU received from the PICC
	 */
	public boolean changeKey(byte keyNo, KeyType newType, byte[] newKey, byte[] oldKey) {
		return changeKey(keyNo, (byte) 0x00, newType, newKey, oldKey, skey);
	}
	
	public boolean changeKey(byte keyNo, byte keyVersion, KeyType newType, byte[] newKey, byte[] oldKey) {
		return changeKey(keyNo, keyVersion, newType, newKey, oldKey, skey);
	}

	// version is 1 separate byte for AES, and the LSBit of each byte for DES keys
	private boolean changeKey(byte keyNo, byte keyVersion, KeyType type, byte[] newKey, byte[] oldKey, byte[] sessionKey) {
		if (!validateKey(newKey, type)
				|| Arrays.equals(aid, new byte[3]) && keyNo != 0x00
				|| kno != (keyNo & 0x0F)
				&& (oldKey == null
				|| ktype == KeyType.DES && oldKey.length != 8
				|| ktype == KeyType.TDES && oldKey.length != 16
				|| ktype == KeyType.TKTDES && oldKey.length != 24
				|| ktype == KeyType.AES && oldKey.length != 16)) {
			// basic checks to mitigate the possibility of messing up the keys
			System.err.println("You're doing it wrong, chief! (changeKey: check your args)");
			this.code = Response.WRONG_ARGUMENT.getCode();
			return false;
		}

		byte[] plaintext = null;
		byte[] ciphertext = null;
		int nklen = type == KeyType.TKTDES ? 24 : 16;  // length of new key

		switch (ktype) {
		case DES:
		case TDES:
			plaintext = type == KeyType.TKTDES ? new byte[32] : new byte[24];
			break;
		case TKTDES:
		case AES:
			plaintext = new byte[32];
			break;
		default:
			assert false : ktype; // this point should never be reached
		}
		if (type == KeyType.AES) {
			plaintext[16] = keyVersion;
		} else {
			setKeyVersion(newKey, 0, newKey.length, keyVersion);
		}
		System.arraycopy(newKey, 0, plaintext, 0, newKey.length);
		if (type == KeyType.DES) {
			// 8-byte DES keys accepted: internally have to be handled w/ 16 bytes
			System.arraycopy(newKey, 0, plaintext, 8, newKey.length);
			newKey = Arrays.copyOfRange(plaintext, 0, 16);
		}

		// tweak for when changing PICC master key
		if (Arrays.equals(aid, new byte[3])) {
			switch (type) {
			case TKTDES:
				keyNo = 0x40;
				break;
			case AES:
				keyNo = (byte) 0x80;
				break;
			default:
				break;
			}
		}

		if ((keyNo & 0x0F) != kno) {
			for (int i = 0; i < newKey.length; i++) {
				plaintext[i] ^= oldKey[i % oldKey.length];
			}
		}

		byte[] tmpForCRC;
		byte[] crc;
		int addAesKeyVersionByte = type == KeyType.AES ? 1 : 0;

		switch (ktype) {
		case DES:
		case TDES:
			crc = CRC16.get(plaintext, 0, nklen + addAesKeyVersionByte);
			System.arraycopy(crc, 0, plaintext, nklen + addAesKeyVersionByte, 2);

			if ((keyNo & 0x0F) != kno) {
				crc = CRC16.get(newKey);
				System.arraycopy(crc, 0, plaintext, nklen + addAesKeyVersionByte + 2, 2);
			}

			ciphertext = send(sessionKey, plaintext, ktype, null);
			break;
		case TKTDES:
		case AES:
			tmpForCRC = new byte[1 + 1 + nklen + addAesKeyVersionByte];
			tmpForCRC[0] = (byte) Command.CHANGE_KEY.getCode();
			tmpForCRC[1] = keyNo;
			System.arraycopy(plaintext, 0, tmpForCRC, 2, nklen + addAesKeyVersionByte);
			crc = CRC32.get(tmpForCRC);
			System.arraycopy(crc, 0, plaintext, nklen + addAesKeyVersionByte, crc.length);

			if ((keyNo & 0x0F) != kno) {
				crc = CRC32.get(newKey);
				System.arraycopy(crc, 0, plaintext, nklen + addAesKeyVersionByte + 4, crc.length);
			}

			ciphertext = send(sessionKey, plaintext, ktype, iv);
			iv = Arrays.copyOfRange(ciphertext, ciphertext.length - iv.length, ciphertext.length);
			break;
		default:
			assert false : ktype; // should never be reached
		}

		byte[] apdu = new byte[5 + 1 + ciphertext.length + 1];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.CHANGE_KEY.getCode();
		apdu[4] = (byte) (1 + plaintext.length);
		apdu[5] = keyNo;
		System.arraycopy(ciphertext, 0, apdu, 6, ciphertext.length);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		this.code = response.getSW2();
		feedback(command, response);

		if (this.code != 0x00)
			return false;
		if ((keyNo & 0x0F) == kno) {
			reset();
		} else {
			if (postprocess(response.getBytes(), CommunicationSetting.PLAIN) == null)
				return false;
		}

		return true;
	}

	/**
	 * Set the version on a DES key. Each least significant bit of each byte of
	 * the DES key, takes one bit of the version. Since the version is only
	 * one byte, the information is repeated if dealing with 16/24-byte keys.
	 * 
	 * @param a			1K/2K/3K 3DES
	 * @param offset	start position of the key within a
	 * @param length	key length
	 * @param version	the 1-byte version
	 */
	private static void setKeyVersion(byte[] a, int offset, int length, byte version) {
		if (length == 8 || length == 16 || length == 24) {
			for (int i = offset + length - 1, j = 0; i >= offset; i--, j = (j + 1) % 8) {
				a[i] &= 0xFE;
				a[i] |= ((version >>> j) & 0x01);
			}
		}
	}

	/**
	 * Read the current version of a key stored in the PICC.
	 * <p>
	 * Note that the key version should be set when changing a key
	 * since this command will allow to see the parity bits of the
	 * DES/3DES keys. It can be set to a default value.
	 * <p>
	 * To change the version of a key the {@linkplain #changeKey()} command
	 * should be used.
	 * 
	 * @param keyNo	the key number
	 * @return		the 1-byte version of the key
	 */
	public byte getKeyVersion(byte keyNo) {
		byte[] apdu = new byte[7];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.GET_KEY_VERSION.getCode();
		apdu[4] = 0x01;
		apdu[5] = keyNo;

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		byte[] ret = postprocess(response.getBytes(), CommunicationSetting.PLAIN);
		if (ret.length != 1)
			return FAKE_NO;
		else
			return ret[0];
	}

	/**
	 * Create a new application.
	 * Requires the PICC-level AID to be selected (00 00 00).
	 * 
	 * @param aid	3-byte AID
	 * @param amks	application master key settings
	 * @param nok	number of keys (concatenated with 0x40 or 0x80 for 3K3DES and AES respectively)
	 * @return		<code>true</code> on success, <code>false</code> otherwise
	 */
	public boolean createApplication(byte[] aid, byte amks, byte nok) {
		byte[] apdu = new byte[11];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.CREATE_APPLICATION.getCode();
		apdu[4] = 0x05;
		System.arraycopy(aid, 0, apdu, 5, 3);
		apdu[8] = amks;
		apdu[9] = nok;

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Delete an application.
	 * Depending on the PICC master key settings, an authentication is required
	 * either with the PICC master key or with the application master key.
	 * 
	 * @param aid	the 3-byte AID of the application to delete
	 * @return		{@code true} on success, {@code false} otherwise
	 */
	public boolean deleteApplication(byte[] aid) {
		byte[] apdu = new byte[9];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.DELETE_APPLICATION.getCode();
		apdu[4] = 0x03;
		System.arraycopy(aid, 0, apdu, 5, 3);

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		byte[] ret = postprocess(response.getBytes(), CommunicationSetting.PLAIN);
		if (ret != null) {
			System.out.println("ret is null");
			if (this.aid == aid)
				reset();
			return true;
		}
		System.out.println("ret is NOT null");
		return false;
	}

	/**
	 * Get the application identifiers of all the active applications.
	 * Each AID is 3 bytes. The PICC-level AID must be currently selected.
	 * 
	 * @return	the byte array with the AIDs, or {@code null} on error
	 */
	public byte[] getApplicationsIds() {
		byte[] fullResp = new byte[3 * 28 + 8 + 2];
		int index = 0;

		byte[] apdu = new byte[] {(byte) 0x90, (byte) 0x6A, 0x00, 0x00, 0x00};
		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);
		if (code == 0x00) {
			System.arraycopy(response.getBytes(), 0, fullResp, index, response.getBytes().length);
			index += response.getBytes().length;
		} else if (code == 0xAF) {
			System.arraycopy(response.getData(), 0, fullResp, index, response.getData().length);
			index += response.getData().length;
		} else {
			return null;
		}

		while (response.getSW2() == 0xAF) {
			apdu[1] = (byte) Command.MORE.getCode();
			command = new CommandAPDU(apdu);
			response = transmit(command);
			code = response.getSW2();
			feedback(command, response);
			if (code == 0x00) {
				System.arraycopy(response.getBytes(), 0, fullResp, index, response.getBytes().length);
				index += response.getBytes().length;
			} else if (code == 0xAF) {
				System.arraycopy(response.getData(), 0, fullResp, index, response.getData().length);
				index += response.getData().length;
			} else {
				return null;
			}
		}
		byte[] ret = new byte[index];
		System.arraycopy(fullResp, 0, ret, 0, index);

		return postprocess(ret, CommunicationSetting.PLAIN);
	}

	/**
	 * The free memory available on the card.
	 * 
	 * @return 3 bytes LSB on success, or {@code null} on error
	 */
	public byte[] freeMemory() {
		byte[] apdu = new byte[5];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.FREE_MEMORY.getCode();

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN);
	}

	/**
	 * ????? TODO (variable result? ciphered?)
	 * @return
	 */
	public byte[] getDFNames() {
		byte[] apdu = new byte[5];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.GET_DF_NAMES.getCode();

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN);
	}

	/**
	 * Get information about the settings of keys.
	 * 
	 * @return	2-byte array (key-settings||max-keys),
	 * 			or {@code null} on error
	 */
	public byte[] getKeySettings() {
		byte[] apdu = new byte[5];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.GET_KEY_SETTINGS.getCode();

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN);
	}

	/**
	 * Select the PICC or a specific application for further access.
	 * The authentication state is lost.
	 * 
	 * @param aid	the 3-byte AID
	 * @return		{@code true} on success, {@code false} otherwise
	 */
	public boolean selectApplication(byte[] aid) {
		byte[] apdu = new byte[9];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.SELECT_APPLICATION.getCode();
		apdu[4] = 0x03;
		System.arraycopy(aid, 0, apdu, 5, 3);

		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		reset();
		if (code != 0x00)
			return false;
		this.aid = aid;
		return true;
	}

	/**
	 * Release the allocated user memory on the PICC. This will delete all
	 * the applications and respective files. The PICC master key and
	 * the PICC master key settings are kept.
	 * 
	 * <p>A previous authentication with the PICC master key is required.
	 * 
	 * @return {@code true} on success, {@code false} otherwise
	 */
	public boolean formatPICC() {
		byte[] apdu = new byte[5];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.FORMAT_PICC.getCode();

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Get manufacturing related data.
	 * 
	 * @return	the data on success, {@code null} otherwise
	 * @see #parseGetVersion(byte[])
	 */
	public byte[] getVersion() {
		byte[] fullResp = new byte[7 + 7 + 14 + 8 + 2];
		int index = 0;
		CommandAPDU command;
		ResponseAPDU response;

		// 1st frame
		byte[] apdu = new byte[] {
				(byte) 0x90,
				(byte) Command.GET_VERSION.getCode(),
				0x00,
				0x00,
				0x00
		};
		preprocess(apdu, CommunicationSetting.PLAIN);
		command = new CommandAPDU(apdu);
		response = transmit(command);
		code = response.getSW2();
		feedback(command, response);
		System.arraycopy(response.getData(), 0, fullResp, 0, response.getData().length);
		index += response.getData().length;

		if (response.getSW2() == 0xAF) {

			// second frame
			apdu[1] = (byte) Command.MORE.getCode();
			command = new CommandAPDU(apdu);
			response = transmit(command);
			code = response.getSW2();
			feedback(command, response);
			System.arraycopy(response.getData(), 0, fullResp, 7, response.getData().length);
			index += response.getData().length;

			if (response.getSW2() == 0xAF) {

				// third frame
				command = new CommandAPDU(apdu);
				response = transmit(command);
				code = response.getSW2();
				feedback(command, response);
				System.arraycopy(response.getBytes(), 0, fullResp, 14, response.getBytes().length);
				index += response.getBytes().length;

				// postprocessing: doesn't always have a CMAC attached
				byte[] ret = new byte[index];
				System.arraycopy(fullResp, 0, ret, 0, index);
				return postprocess(ret, CommunicationSetting.PLAIN);
			}
		}

		return null;
	}

	/**
	 * Get the card UID.
	 * <p>
	 * Requires a previous authentication.
	 * 
	 * @return	the card UID on success, {@code null} on error
	 */
	public byte[] getCardUID() {
		byte[] apdu = new byte[5];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.GET_CARD_UID.getCode();

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), 7, CommunicationSetting.ENCIPHERED);
	}

	/**
	 * Get the file identifiers of all the active files within the
	 * currently selected application.
	 * 
	 * @return the identifiers of files, or <code>null</code> on error
	 */
	public byte[] getFileIds() {
		byte[] apdu = new byte[5];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) 0x6F;
		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN);
	}

	/**
	 * Get information on the properties of a specific file.
	 * 
	 * @param fileNo	the file number
	 * @return			the properties of the file on success, {@code null} otherwise
	 */
	public byte[] getFileSettings(int fileNo) {
		//TODO: create some file object that allows to query properties?
		byte[] apdu = new byte[7];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) 0xF5;
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x01;
		apdu[5] = (byte) fileNo;
		apdu[6] = 0x00;

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN);
	}

	/**
	 * Change the file settings of a file.
	 * <p>
	 * Requires a preceding authentication with the CAR key.
	 * 
	 * @param fileNo	the file number
	 * @param commSett	the communication settings for this file (0/1/3)
	 * @param ar1		access rights: RW/CAR
	 * @param ar2		access rights: R/W
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean changeFileSettings(byte fileNo, byte commSett, byte ar1, byte ar2) {
		CommunicationSetting cs = getFileCommSett(fileNo, false, true, false, false);
		if (cs == null)
			return false;

		byte[] apdu = new byte[10];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.CHANGE_FILE_SETTINGS.getCode();
		apdu[4] = 0x04;
		apdu[5] = fileNo;
		apdu[6] = commSett;
		apdu[7] = ar1;
		apdu[8] = ar2;

		apdu = preprocess(apdu, 1, cs);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		// get rid of cache
		if (response.getSW2() == 0x00 && fileNo == this.fileNo) {
			this.fileNo = FAKE_NO;
			this.fileSett = null;
		}

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Create a file for the storage of unformatted user data.
	 * Memory is allocated in multiples of 32 bytes.
	 * 
	 * @param payload	7-byte array, with the following content:
	 * 					<br>file number (1 byte),
	 * 					<br>communication settings (1 byte),
	 * 					<br>access rights (2 bytes),
	 * 					<br>file size (3 bytes)
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean createStdDataFile(byte[] payload) {
		return createDataFile(payload, (byte) Command.CREATE_STD_DATA_FILE.getCode());
	}

	/**
	 * Create a file for the storage of unformatted user data.
	 * <p>
	 * Supports an integrated backup mechanism. Consumes double the
	 * memory in comparison to {@linkplain #createStdDataFile(byte[])}.
	 * Requires a {@linkplain #commitTransaction()} to validate writes.
	 * 
	 * @param payload	7-byte array, with the following content:
	 * 					<br>file number (1 byte),
	 * 					<br>communication settings (1 byte),
	 * 					<br>access rights (2 bytes),
	 * 					<br>file size (3 bytes)
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean createBackupDataFile(byte[] payload) {
		return createDataFile(payload, (byte) Command.CREATE_BACKUP_DATA_FILE.getCode());
	}

	/* Support method for createStdDataFile/createBackupDataFile. */
	private boolean createDataFile(byte[] payload, byte cmd) {
		byte[] apdu = new byte[13];
		apdu[0] = (byte) 0x90;
		apdu[1] = cmd;
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x07;
		System.arraycopy(payload, 0, apdu, 5, 7);
		apdu[12] = 0x00;

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	//public boolean createValueFile(int fileNo, CommunicationSetting cs, byte ar1, byte ar2, int, int, int, boolean)

	/**
	 * Create a value file, used for the storage and
	 * manipulation of a 32-bit signed integer value.
	 * 
	 * @param payload	17-byte byte array, with the following contents:
	 * 					<br>file number (1 byte),
	 * 					<br>communication settings (1 byte),
	 * 					<br>access rights (2 bytes),
	 * 					<br>lower limit (4 bytes),
	 * 					<br>upper limit (4 bytes),
	 * 					<br>value (4 bytes),
	 * 					<br>limited credit enabled (1 byte)
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean createValueFile(byte[] payload) {
		byte[] apdu = new byte[23];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) 0xCC;
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x11;
		System.arraycopy(payload, 0, apdu, 5, 17);
		apdu[22] = 0x00;

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Create a file for storage of similar structural data
	 * (e.g. loyalty programs). Once the file is completely full
	 * with data records, it cannot be written to unless it is cleared.
	 * The file size is single record size * maximum number of records.
	 * <p>
	 * Linear record files include a backup mechanism and
	 * require validation using {@linkplain #commitTransaction()}.
	 * 
	 * @param payload	10-byte array with the following contents:
	 * 					<br>file number (1 byte),
	 * 					<br>communication settings (1 byte),
	 * 					<br>access rights (2 bytes: RW||CAR||R||W),
	 * 					<br>size of a single record size (3 bytes LSB),
	 * 					<br>maximum amount of records (3 bytes LSB)
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean createLinearRecordFile(byte[] payload) {
		return createRecordFile(payload, (byte) Command.CREATE_LINEAR_RECORD_FILE.getCode());
	}

	/**
	 * Create a file for storage of similar structural data
	 * (e.g. logging transactions). Once the file is completely full
	 * with data records, the PICC automatically overwrites the oldest entry.
	 * The file size is single record size * maximum number of records.
	 * <p>
	 * Linear record files include a backup mechanism and
	 * require validation using {@linkplain #commitTransaction()}.
	 * The backup mechanism consumes one of the records, which
	 * cannot be used to store data.
	 * 
	 * @param payload	10-byte array with the following contents:
	 * 					<br>file number (1 byte),
	 * 					<br>communication settings (1 byte),
	 * 					<br>access rights (2 bytes: RW||CAR||R||W),
	 * 					<br>size of a single record size (3 bytes LSB),
	 * 					<br>maximum amount of records (3 bytes LSB)
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean createCyclicRecordFile(byte[] payload) {
		return createRecordFile(payload, (byte) Command.CREATE_CYCLIC_RECORD_FILE.getCode());
	}

	/* Support method for createLinearRecordFile/createCyclicRecordFile. */
	private boolean createRecordFile(byte[] payload, byte cmd) {
		byte[] apdu = new byte[16];
		apdu[0] = (byte) 0x90;
		apdu[1] = cmd;
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x0A;
		System.arraycopy(payload, 0, apdu, 5, 10);
		apdu[15] = 0x00;

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Permanently deactivate a file. The file number can be reused but
	 * the allocated memory will remain occupied.
	 * 
	 * @return	{@code true} on success
	 */
	public boolean deleteFile(byte fileNo) {
		byte[] apdu = new byte[] {
				(byte) 0x90,
				(byte) Command.DELETE_FILE.getCode(),
				0x00,
				0x00,
				0x01,
				fileNo,
				0x00
		};
		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);

		if (this.fileNo == fileNo) {
			fileNo = FAKE_NO;
			fileSett = null;
		}

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Read data from standard data files or backup data files.
	 * 
	 * @param payload	a byte array with the following contents:
	 * 					<br>file number (1 byte),
	 * 					<br>offset within the file being read (3 bytes LSB),
	 * 					<br>length of the data to read (3 byte LSB)
	 * 					When the length of the data being read is 0x000000,
	 * 					the entire file is read, starting from offset.
	 * @return			{@code true} on success, {@code false otherwise}
	 */
	public byte[] readData(byte[] payload) {
		return read(payload, Command.READ_DATA.getCode());
	}

	/**
	 * Write data to standard data files or backup data files.
	 * <p>
	 * When writing to backup data files, a {@linkplain #commitTransaction()}
	 * is required to validate the changes.
	 * 
	 * @param payload	a byte array with the following contents:
	 * 					<br>file number (1 byte),
	 * 					<br>offset within the file being written (3 bytes LSB),
	 * 					<br>length of the data (3 byte LSB),
	 * 					<br>the data (1+ bytes)
	 * @return			{@code true} on success, {@code false otherwise}
	 */
	public boolean writeData(byte[] payload) {
		return write(payload, (byte) Command.WRITE_DATA.getCode());
	}

	/**
	 * Read the currently stored value, from
	 * value file number {@code fileNo}.
	 * 
	 * @param fileNo	the file number
	 * @return			the stored value, or {@code null} on error
	 */
	public Integer getValue(byte fileNo) {
		CommunicationSetting cs = getFileCommSett(fileNo, true, false, true, true);
		if (cs == null)
			return null;

		byte[] apdu = new byte[7];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.GET_VALUE.getCode();
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x01;
		apdu[5] = fileNo;
		apdu[6] = 0x00;

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		byte[] ret = postprocess(response.getBytes(), 4, cs);
		if (ret == null)
			return null;

		return BitOp.lsbToInt(ret, 0);
	}

	/**
	 * Increase a value stored in a value file.
	 * A preceding authentication with the read&write access key is required.
	 * The stored value will not be updated until a commit transaction
	 * command is issued.
	 * 
	 * @param fileNo	the number of the file
	 * @param value		the amount to increase
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean credit(byte fileNo, int value) {
		CommunicationSetting cs = getFileCommSett(fileNo, true, false, true, true);
		if (cs == null)
			return false;

		byte[] apdu = new byte[11];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) 0x0C;
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x05;
		apdu[5] = fileNo;
		BitOp.intToLsb(value, apdu, 6);
		apdu[10] = 0x00;

		apdu = preprocess(apdu, 1, cs);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Decrease a value stored in a value file.
	 * The value will not be updated on the card until a
	 * commit transaction command is issued.
	 * 
	 * @param fileNo	the number of the file
	 * @param value		the amount to decrease
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean debit(byte fileNo, int value) {
		CommunicationSetting cs = getFileCommSett(fileNo, true, false, true, true);
		if (cs == null)
			return false;

		byte[] apdu = new byte[11];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.DEBIT.getCode();
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x05;
		apdu[5] = fileNo;
		BitOp.intToLsb(value, apdu, 6);
		apdu[10] = 0x00;

		apdu = preprocess(apdu, 1, cs);  // do not cipher keyNo
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Allows a limited increase of a value stored in a value file.
	 * It is necessary to validate the transaction with a
	 * {@linkplain #commitTransaction()}.
	 * <p>
	 * This can only be performed after a transaction where at least
	 * one debit action took place. The sum of the debits is the maximum
	 * value that can be increased.
	 * <p>
	 * Requires R or RW access.
	 * 
	 * @param fileNo	the number of the file
	 * @param value		the amount to increase
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean limitedCredit(byte fileNo, int value) {
		CommunicationSetting cs = getFileCommSett(fileNo, true, false, true, true);
		if (cs == null)
			return false;

		byte[] apdu = new byte[11];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.LIMITED_CREDIT.getCode();
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x05;
		apdu[5] = fileNo;
		BitOp.intToLsb(value, apdu, 6);
		apdu[10] = 0x00;

		apdu = preprocess(apdu, 1, cs); // do not cipher keyNo
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Write data to a record in linear record files or cyclic record files.
	 * <p>
	 * Requires a preceding authentication with the
	 * W or with the RW access key. After writing a record, a
	 * {@linkplain #commitTransaction()} is required to validate the write.
	 * Multiples writes are done to the same record until the
	 * operations are validated.
	 * <p>
	 * If a {@linkplain #clearRecordFile(byte)} command is issued,
	 * it must be validated or invalidated before attempting to write or
	 * the write will fail.
	 * 
	 * @param payload	a byte array with the following contents:
	 * 					<br>file number (1 byte),
	 * 					<br>offset within the record (3 bytes LSB),
	 * 					<br>length of the data to be written (3 bytes LSB),
	 * 					<br>the data (1+ bytes)
	 * @return			{@code true} on success, {@code false otherwise}
	 */
	public boolean writeRecord(byte[] payload) {
		return write(payload, (byte) Command.WRITE_RECORDS.getCode());
	}

	/**
	 * Reads a set of complete records from a linear record file or
	 * from a cyclic record file. Records are read in chronological order,
	 * from the oldest to the newest.
	 * <p>
	 * A read will fail when performed on an empty record file or after a
	 * {@linkplain #clearRecordFile(byte)} yet to be validated/invalidated.
	 * A read fails unless there is data to be returned.
	 * 
	 * @param payload	a byte array with the following contents:
	 * 					<br>file number (1 byte),
	 * 					<br>offset starting from the most recent record (3 bytes LSB),
	 * 					<br>number of records to be read (3 byte LSB)
	 * 					When the length of the data being read is 0x000000,
	 * 					the entire file is read, starting from offset.
	 * @return			{@code true} on success, {@code false otherwise}
	 */
	public byte[] readRecords(byte[] payload) {
		return read(payload, Command.READ_RECORDS.getCode());
	}

	/**
	 * Reset a cyclic record file or a linear record file to empty state.
	 * 
	 * <p>Requires full read-write permission and a
	 * subsequent {@link #commitTransaction()}.
	 * 
	 * @param fileNo	the file number
	 * @return			{@code true} on success, {@code false} otherwise
	 */
	public boolean clearRecordFile(byte fileNo) {
		byte[] apdu = new byte[] {
				(byte) 0x90,
				(byte) Command.CLEAR_RECORD_FILE.getCode(),
				0x00,
				0x00,
				0x01,
				fileNo,
				0x00
		};

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Validate all previous writes to value files, backup data files,
	 * linear records files and cyclic record files, within one application.
	 * 
	 * @return	{@code true} on success
	 */
	public boolean commitTransaction() {
		byte[] apdu = new byte[5];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.COMMIT_TRANSACTION.getCode();

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	/**
	 * Invalidate all previous writes to value files, backup data files,
	 * linear records files and cyclic record files, within one application.
	 * It may also be used after a clear record file to
	 * invalidate the clearance.
	 * 
	 * @return {@code true} on success, {@code false} otherwise
	 */
	public boolean abortTransaction() {
		byte[] apdu = new byte[5];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) Command.ABORT_TRANSACTION.getCode();

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		code = response.getSW2();
		feedback(command, response);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	private byte[] preprocess(byte[] apdu, CommunicationSetting commSett) {
		return preprocess(apdu, 0, commSett);
	}

	/**
	 * Pre-process command APDU before sending it to PICC.
	 * The global IV is updated.
	 * 
	 * <p>If not authenticated, the APDU is immediately returned.
	 * 
	 * @param apdu		the APDU
	 * @param offset	the offset of data within the command (for enciphered).
	 * 					For example, credit does not encrypt the 1-byte
	 * 					key number so the offset would be 1.
	 * @param commSett	the communication mode
	 * @return			For PLAIN, returns the APDU. For MACed, returns the
	 * 					APDU with the CMAC appended. For ENCIPHERED,
	 * 					returns the ciphered version of the APDU.
	 * 					If an error occurs, returns <code>null</code>.
	 */
	private byte[] preprocess(byte[] apdu, int offset, CommunicationSetting commSett) {
		if (commSett == null) {
			System.err.println("preprocess: commSett is null");
			return null;
		}
		if (skey == null) {
			System.err.println("preprocess: skey is null");
			return apdu;
		}

		switch (commSett) {
		case PLAIN:
			return preprocessPlain(apdu);
		case MACED:
			return preprocessMaced(apdu, offset);
		case ENCIPHERED:
			return preprocessEnciphered(apdu, offset);
		default:
			return null;  // never reached
		}
	}

	// update global IV
	private byte[] preprocessPlain(byte[] apdu) {
		if (ktype == KeyType.TKTDES || ktype == KeyType.AES) {
			iv = calculateApduCMAC(apdu, skey, iv, ktype);
		}

		return apdu;
	}

	// update global IV and append
	//(2K3)DES?
	private byte[] preprocessMaced(byte[] apdu, int offset) {
		switch (ktype) {
		case DES:
		case TDES:
			byte[] mac = calculateApduMACC(apdu, skey, offset);

			byte[] ret1 = new byte[apdu.length + 4];
			System.arraycopy(apdu, 0, ret1, 0, apdu.length);
			System.arraycopy(mac, 0, ret1, apdu.length - 1, 4);
			ret1[4] += 4;

			return ret1;
		case TKTDES:
		case AES:
			iv = calculateApduCMAC(apdu, skey, iv, ktype);

			byte[] ret2 = new byte[apdu.length + 8];
			System.arraycopy(apdu, 0, ret2, 0, apdu.length);
			System.arraycopy(iv, 0, ret2, apdu.length - 1, 8);  // trailing 00
			ret2[4] += 8;

			return ret2;
		default:
			return null;
		}
	}

	// calculate CRC and append, encrypt, and update global IV
	private byte[] preprocessEnciphered(byte[] apdu, int offset) {
		byte[] ciphertext = encryptApdu(apdu, offset, skey, iv, ktype);

		byte[] ret = new byte[5 + offset + ciphertext.length + 1];
		System.arraycopy(apdu, 0, ret, 0, 5 + offset);
		System.arraycopy(ciphertext, 0, ret, 5 + offset, ciphertext.length);
		ret[4] = (byte) (offset + ciphertext.length);

		if (ktype == KeyType.TKTDES || ktype == KeyType.AES) {
			iv = new byte[iv.length];
			System.arraycopy(ciphertext, ciphertext.length - iv.length, iv, 0, iv.length);
		}

		return ret;
	}

	private byte[] postprocess(byte[] apdu, CommunicationSetting commSett) {
		return postprocess(apdu, -1, commSett);
	}

	/**
	 * Some commands require post-processing. It can be used to check if
	 * the received CMAC is correct, or to decipher a response APDU and
	 * verify if the CRC is correct. The global IV is updated.
	 * 
	 * <p>If not authenticated, the APDU is immediately returned.
	 * This also happens if the APDU length is 2 and the status code is
	 * different from success (0x00).
	 * 
	 * FIXME: return only relevant data from apdu
	 * FIXME: handle limitedCredit boundary error, denied permisson, .......
	 * 
	 * @param apdu		the APDU
	 * @param length	the length of data (0 to beginning of CRC32)
	 * @param commSett	the communication mode
	 * @return			For PLAIN and MACed, it returns the APDU (without MAC/CMAC and status code 91 xx).
	 * 					For ENCIPHERED, returns the deciphered APDU.
	 * 					If an error occurs, returns <code>null</code>.
	 */
	private byte[] postprocess(byte[] apdu, int length, CommunicationSetting commSett) {
		if (commSett == null) {
			System.err.println("postprocess: commSett is null");
			return null;
		}
		if (apdu[apdu.length - 1] != 0x00) {
			System.err.println("postprocess: status <> 00 (" + Response.getResponse(apdu[apdu.length - 1]) + ")");
			reset();
			return null;
		}
		if (skey == null) {
			System.err.println("postprocess: skey is null");
			return Arrays.copyOfRange(apdu, 0, apdu.length - 2);
		}

		switch (commSett) {
		case PLAIN:
			if (ktype == KeyType.DES || ktype == KeyType.TDES)
				return Arrays.copyOfRange(apdu, 0, apdu.length - 2);  //?needed?
			// no "break;"
		case MACED:
			return postprocessMaced(apdu);
		case ENCIPHERED:
			return postprocessEnciphered(apdu, length);
		default:
			return null;  // never reached
		}
	}

	private byte[] postprocessMaced(byte[] apdu) {
		switch (ktype) {
		case DES:
		case TDES:
			assert apdu.length >= 4 + 2;

			byte[] mac = calculateApduMACR(apdu, skey);
			for (int i = 0, j = apdu.length - 6; i < 4 && j < apdu.length - 2; i++, j++) {
				if (mac[i] != apdu[j]) {
					return null;
				}
			}

			return Arrays.copyOfRange(apdu, 0, apdu.length - 4 - 2);
		case TKTDES:
		case AES:
			assert apdu.length >= 8 + 2;

			byte[] block2 = new byte[apdu.length - 9];
			System.arraycopy(apdu, 0, block2, 0, apdu.length - 10);
			block2[block2.length - 1] = apdu[apdu.length - 1];

			CMAC.Type cmacType = ktype == KeyType.AES ? CMAC.Type.AES : CMAC.Type.TKTDES;
			byte[] cmac = CMAC.get(cmacType, skey, block2, iv);
			for (int i = 0, j = apdu.length - 10; i < 8 && j < apdu.length - 2; i++, j++) {
				if (cmac[i] != apdu[j]) {
					System.err.println("Received CMAC does not match calculated CMAC.");
					return null;
				}
			}
			iv = cmac;

			return Arrays.copyOfRange(apdu, 0, apdu.length - 8 - 2);
		default:
			return null;  // never reached
		}
	}

	private byte[] postprocessEnciphered(byte[] apdu, int length) {
		assert apdu.length >= 2;

		byte[] ciphertext = Arrays.copyOfRange(apdu, 0, apdu.length - 2);
		byte[] plaintext = recv(skey, ciphertext, ktype, iv);

		byte[] crc;
		switch (ktype) {
		case DES:
		case TDES:
			crc = calculateApduCRC16R(plaintext, length);
			break;
		case TKTDES:
		case AES:
			iv = Arrays.copyOfRange(apdu, apdu.length - 2 - iv.length, apdu.length - 2);
			crc = calculateApduCRC32R(plaintext, length);
			break;
		default:
			return null;
		}
		for (int i = 0; i < crc.length; i++) {
			if (crc[i] != plaintext[i + length]) {
				System.err.println("Received CMAC does not match calculated CMAC.");
				return null;
			}
		}

		return Arrays.copyOfRange(plaintext, 0, length);
	}

	private static byte[] calculateApduCMAC(byte[] apdu, byte[] sessionKey, byte[] iv, KeyType type) {
		byte[] block;

		if (apdu.length == 5) {
			block = new byte[apdu.length - 4];
		} else {
			// trailing 00h exists
			block = new byte[apdu.length - 5];
			System.arraycopy(apdu, 5, block, 1, apdu.length - 6);
		}
		block[0] = apdu[1];

		switch (type) {
		case TKTDES:
			return CMAC.get(CMAC.Type.TKTDES, sessionKey, block, iv);
		case AES:
			return CMAC.get(CMAC.Type.AES, sessionKey, block, iv);
		default:
			return null;
		}
	}

	// calculated only over data (header also left out: e.g. could be keyNo)
	private static byte[] calculateApduMACC(byte[] apdu, byte[] skey, int offset) {
		int datalen = apdu.length == 5 ? 0 : apdu.length - 6 - offset;
		byte[] block = new byte[datalen % 8 == 0 ? datalen : (datalen / 8 + 1) * 8];
		System.arraycopy(apdu, 5 + offset, block, 0, apdu.length - 6 - offset);

		return calculateMAC(block, skey);
	}

	// calculated only over data
	private static byte[] calculateApduMACR(byte[] apdu, byte[] skey) {
		int datalen = apdu.length - 6;
		int blockSize = datalen % 8 == 0 ? datalen : (datalen / 8 + 1) * 8;
		byte[] block = new byte[blockSize];
		System.arraycopy(apdu, 0, block, 0, datalen);

		return calculateMAC(block, skey);
	}

	/**
	 * Calculate the MAC of {@code data}.
	 * <p>
	 * The MAC is calculated using Triple DES encryption. The MAC is
	 * the first half of the last block of ciphertext.
	 * 
	 * @param data	the data (length is multiple of 8)
	 * @param key	the 8/16-byte key
	 * @return		the 4-byte MAC
	 */
	/* Support method for calculateApduMAC(C|R). */
	private static byte[] calculateMAC(byte[] data, byte[] key) {
		byte[] key24 = new byte[24];
		System.arraycopy(key, 0, key24, 16, 8);
		System.arraycopy(key, 0, key24, 8, 8);
		System.arraycopy(key, 0, key24, 0, key.length);

		byte[] ciphertext = TripleDES.encrypt(new byte[8], key24, data);

		return Arrays.copyOfRange(ciphertext, ciphertext.length - 8, ciphertext.length - 4);
	}

	// CRC16 calculated only over data
	private static byte[] calculateApduCRC16C(byte[] apdu, int offset) {
		if (apdu.length == 5) {
			return CRC16.get(new byte[0]);
		} else {
			return CRC16.get(apdu, 5 + offset, apdu.length - 5 - offset - 1);
		}
	}

	private static byte[] calculateApduCRC16R(byte[] apdu, int length) {
		byte[] data = new byte[length];

		System.arraycopy(apdu, 0, data, 0, length);

		return CRC16.get(data);
	}

	// CRC32 calculated over INS+header+data
	private static byte[] calculateApduCRC32C(byte[] apdu) {
		byte[] data;

		if (apdu.length == 5) {
			data = new byte[apdu.length - 4];
		} else {
			data = new byte[apdu.length - 5];
			System.arraycopy(apdu, 5, data, 1, apdu.length - 6);
		}
		data[0] = apdu[1];

		return CRC32.get(data);
	}

	private static byte[] calculateApduCRC32R(byte[] apdu, int length) {
		byte[] data = new byte[length + 1];

		System.arraycopy(apdu, 0, data, 0, length);// response code is at the end

		return CRC32.get(data);
	}

	/* Only data is encrypted. Headers are left out (e.g. keyNo for credit). */
	private static byte[] encryptApdu(byte[] apdu, int offset, byte[] sessionKey, byte[] iv, KeyType type) {
		int blockSize = type == KeyType.AES ? 16 : 8;
		int payloadLen = apdu.length - 6;
		byte[] crc = null;

		switch (type) {
		case DES:
		case TDES:
			crc = calculateApduCRC16C(apdu, offset);
			break;
		case TKTDES:
		case AES:
			crc = calculateApduCRC32C(apdu);
			break;
		}

		int padding = 0;  // padding=0 if block length is adequate
		if ((payloadLen - offset + crc.length) % blockSize != 0)
			padding = blockSize - (payloadLen - offset + crc.length) % blockSize;
		int ciphertextLen = payloadLen - offset + crc.length + padding;
		byte[] plaintext = new byte[ciphertextLen];
		System.arraycopy(apdu, 5 + offset, plaintext, 0, payloadLen - offset);
		System.arraycopy(crc, 0, plaintext, payloadLen - offset, crc.length);

		return send(sessionKey, plaintext, type, iv);
	}

	/**
	 * Find which communication mode to use when operating on a file.
	 * The arguments depend on the operation being performed.
	 * 
	 * @param fileNo	the file number
	 * @param rw		read-write access
	 * @param car		change access rights
	 * @param r			read access
	 * @param w			write access
	 * @return			the communication mode on success, {@code null} on error
	 */
	private CommunicationSetting getFileCommSett(byte fileNo, boolean rw, boolean car, boolean r, boolean w) {
		if (updateFileSett(fileNo, false) == false)
			return null;

		boolean isAuthKey = false;
		boolean isFreeAccess = false;

		if (rw) {
			if ((fileSett[2] & 0xF0) >>> 4 == kno) {
				isAuthKey = true;
			} else if ((fileSett[2] & 0xF0) == 0xE0) {
				isFreeAccess = true;
			}
		}

		if (car) {
			if ((fileSett[2] & 0x0F) == kno) {
				return CommunicationSetting.ENCIPHERED;
			} else if ((fileSett[2] & 0x0F) == 0x0E) {
				//isFreeAccess = true;
				return CommunicationSetting.PLAIN;
			}
		}

		if (r) {
			if ((fileSett[3] & 0xF0) >>> 4 == kno) {
				isAuthKey = true;
			} else if ((fileSett[3] & 0xF0) == 0xE0) {
				isFreeAccess = true;
			}
		}

		if (w) {
			if ((fileSett[3] & 0x0F) == kno) {
				isAuthKey = true;
			} else if ((fileSett[3] & 0x0F) == 0x0E) {
				isFreeAccess = true;
			}
		}

		if (isAuthKey) {
			// at least one of the ARs matches the authentication keyNo
			return getFileCommSett(fileSett[1]);
		} else if (isFreeAccess) {
			// at least one of the ARs allows free access
			return CommunicationSetting.PLAIN;
		} else {
			// access is denied
			return null;
		}
	}

	/* Support method for getFileCommSett(rw, car, r, w). */
	private CommunicationSetting getFileCommSett(byte cs) {
		switch (cs) {
		case 0x00:
			return CommunicationSetting.PLAIN;
		case 0x01:
			return CommunicationSetting.MACED;
		case 0x03:
			return CommunicationSetting.ENCIPHERED;
		default:
			return null;
		}
	}
	
	/**
	 * Called internally by some methods to make sure the file settings
	 * are up-to-date. Avoids multiple calls to the PICC to fetch the
	 * settings of the file being manipulated.
	 * 
	 * @param fileNo		the file number
	 * @param forceUpdate	force the update?
	 * @return				{@code true} on success, {@code false} otherwise
	 */
	private boolean updateFileSett(byte fileNo, boolean forceUpdate) {
		if (this.fileNo != fileNo || forceUpdate) {
			byte[] tmp = getFileSettings(fileNo);
			
			if (tmp != null) {
				this.fileNo = fileNo;
				this.fileSett = tmp;
			} else {
				this.fileNo = FAKE_NO;
				this.fileSett = null;
				return false;
			}
		}
		
		return true;
	}

	/* Support method for readData/readRecords. */
	private byte[] read(byte[] payload, int cmd) {

		// record files: file settings could be cached,
		// returning an erroneous number of current records
		if (cmd == 0xBB && !updateFileSett(payload[0], true))
			return null;

		CommunicationSetting cs = getFileCommSett(payload[0], true, false, true, false);
		if (cs == null)
			return null;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int responseLength = findResponseLength(payload, cmd);

		byte[] apdu = new byte[13];
		apdu[0] = (byte) 0x90;
		apdu[1] = (byte) cmd;
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = 0x07;
		System.arraycopy(payload, 0, apdu, 5, 7);
		apdu[12] = 0x00;

		preprocess(apdu, CommunicationSetting.PLAIN);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);
		try {
			baos.write(response.getData());
		} catch (IOException e1) {
			e1.printStackTrace();
			disconnect();
			return null;
		}

		while (response.getSW2() == 0xAF) {
			apdu = new byte[] {(byte) 0x90, (byte) Command.MORE.getCode(), 0x00, 0x00, 0x00};
			command = new CommandAPDU(apdu);
			response = transmit(command);
			feedback(command, response);
			try {
				baos.write(response.getData());
			} catch (IOException e) {
				e.printStackTrace();
				disconnect();
				return null;
			}
		}
		baos.write(response.getBytes(), response.getBytes().length - 2, 2);

		return postprocess(baos.toByteArray(), responseLength, cs);
	}

	/* Support method for read(). Find length of just the data. Retrieved
	 * APDU is likely to be longer due to encryption (e.g. CRC/padding).
	 */
	private int findResponseLength(byte[] payload, int cmd) {
		int responseLength = 0;

		switch (cmd) {
		case 0xBD:  // data files
			int offsetDF = 0;
			byte[] sourceRespLen;

			if (payload[4] != 0 || payload[5] != 0 || payload[6] != 0) {
				sourceRespLen = payload;
			} else {
				sourceRespLen = fileSett;

				offsetDF |= (payload[1] & 0xFF) << 0;
				offsetDF |= (payload[2] & 0xFF) << 8;
				offsetDF |= (payload[3] & 0xFF) << 16;
			}

			responseLength |= (sourceRespLen[6] & 0xff) << 16;
			responseLength |= (sourceRespLen[5] & 0xff) << 8;
			responseLength |= (sourceRespLen[4] & 0xff) << 0;
			responseLength -= offsetDF;
			break;
		case 0xBB:  // record files
			int singleRecordSize = 0;
			int offsetRF = 0;
			int recordsToRead = 0;

			singleRecordSize |= (fileSett[4] & 0xFF) << 0;
			singleRecordSize |= (fileSett[5] & 0xFF) << 8;
			singleRecordSize |= (fileSett[6] & 0xFF) << 16;

			if (payload[4] != 0 || payload[5] != 0 || payload[6] != 0) {
				recordsToRead |= (payload[6] & 0xff) << 16;
				recordsToRead |= (payload[5] & 0xff) << 8;
				recordsToRead |= (payload[4] & 0xff) << 0;
			} else {
				offsetRF |= (payload[1] & 0xFF) << 0;
				offsetRF |= (payload[2] & 0xFF) << 8;
				offsetRF |= (payload[3] & 0xFF) << 16;

				recordsToRead |= (fileSett[10] & 0xFF) << 0;
				recordsToRead |= (fileSett[11] & 0xFF) << 8;
				recordsToRead |= (fileSett[12] & 0xFF) << 16;
				recordsToRead -= offsetRF;
			}

			responseLength = singleRecordSize * recordsToRead;
			break;
		default:
			return -1;  // never reached
		}

		return responseLength;
	}

	/* Support method for writeData/writeRecord. */
	private boolean write(byte[] payload, byte cmd) {
		CommunicationSetting cs = getFileCommSett(payload[0], true, false, false, true);
		if (cs == null)
			return false;

		byte[] apdu;
		byte[] fullApdu = new byte[6 + payload.length];
		fullApdu[0] = (byte) 0x90;
		fullApdu[1] = cmd;
		fullApdu[4] = -1;
		System.arraycopy(payload, 0, fullApdu, 5, payload.length);

		fullApdu = preprocess(fullApdu, 7, cs);  // 7 = 1+3+3 (keyNo+off+len)
		CommandAPDU command;
		ResponseAPDU response;
		int totalPayload = fullApdu.length - 6;
		int payloadSent = 0;

		do {
			int sendThisFrame = totalPayload - payloadSent > 52 ? 52
					: totalPayload - payloadSent;

			//System.out.println(String.format("totalPaylod=%d, payloadSent=%d, sendThisFrame=%d",
			//		totalPayload, payloadSent, sendThisFrame));

			apdu = new byte[6 + sendThisFrame];
			apdu[0] = fullApdu[0];
			apdu[1] = payloadSent == 0 ? fullApdu[1] : (byte) Command.MORE.getCode();
			apdu[4] = (byte) sendThisFrame;
			System.arraycopy(fullApdu, 5 + payloadSent, apdu, 5, sendThisFrame);

			command = new CommandAPDU(apdu);
			response = transmit(command);
			code = response.getSW2();
			feedback(command, response);

			payloadSent += sendThisFrame;
		} while (totalPayload - payloadSent > 0 && code == 0xAF);

		return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
	}

	// IV sent is the global one but it is better to be explicit about it: can be null for DES/3DES
	// if IV is null, then it is set to zeros
	// Sending data that needs encryption.
	private static byte[] send(byte[] key, byte[] data, KeyType type, byte[] iv) {
		switch (type) {
		case DES:
		case TDES:
			return decrypt(key, data, DESMode.SEND_MODE);
		case TKTDES:
			return TripleDES.encrypt(iv == null ? new byte[8] : iv, key, data);
		case AES:
			return AES.encrypt(iv == null ? new byte[16] : iv, key, data);
		default:
			return null;
		}
	}

	// Receiving data that needs decryption.
	private static byte[] recv(byte[] key, byte[] data, KeyType type, byte[] iv) {
		switch (type) {
		case DES:
		case TDES:
			return decrypt(key, data, DESMode.RECEIVE_MODE);
		case TKTDES:
			return TripleDES.decrypt(iv == null ? new byte[8] : iv, key, data);
		case AES:
			return AES.decrypt(iv == null ? new byte[16] : iv, key, data);
		default:
			return null;
		}
	}

	// DES/3DES decryption: CBC send mode and CBC receive mode
	private static byte[] decrypt(byte[] key, byte[] data, DESMode mode) {
		byte[] modifiedKey = new byte[24];
		System.arraycopy(key, 0, modifiedKey, 16, 8);
		System.arraycopy(key, 0, modifiedKey, 8, 8);
		System.arraycopy(key, 0, modifiedKey, 0, key.length);

		/* MF3ICD40, which only supports DES/3DES, has two cryptographic
		 * modes of operation (CBC): send mode and receive mode. In send mode,
		 * data is first XORed with the IV and then decrypted. In receive
		 * mode, data is first decrypted and then XORed with the IV. The PCD
		 * always decrypts. The initial IV, reset in all operations, is all zeros
		 * and the subsequent IVs are the last decrypted/plain block according with mode.
		 * 
		 * MDF EV1 supports 3K3DES/AES and remains compatible with MF3ICD40.
		 */
		byte[] ciphertext = new byte[data.length];
		byte[] cipheredBlock = new byte[8];

		switch (mode) {
		case SEND_MODE:
			// XOR w/ previous ciphered block --> decrypt
			for (int i = 0; i < data.length; i += 8) {
				for (int j = 0; j < 8; j++) {
					data[i + j] ^= cipheredBlock[j];
				}
				cipheredBlock = TripleDES.decrypt(modifiedKey, data, i, 8);
				System.arraycopy(cipheredBlock, 0, ciphertext, i, 8);
			}
			break;
		case RECEIVE_MODE:
			// decrypt --> XOR w/ previous plaintext block
			cipheredBlock = TripleDES.decrypt(modifiedKey, data, 0, 8);
			// implicitly XORed w/ IV all zeros
			System.arraycopy(cipheredBlock, 0, ciphertext, 0, 8);
			for (int i = 8; i < data.length; i += 8) {
				cipheredBlock = TripleDES.decrypt(modifiedKey, data, i, 8);
				for (int j = 0; j < 8; j++) {
					cipheredBlock[j] ^= data[i + j - 8];
				}
				System.arraycopy(cipheredBlock, 0, ciphertext, i, 8);
			}
			break;
		default:
			System.err.println("Wrong way (decrypt)");
			return null;
		}

		return ciphertext;
	}

	// feedback/debug: a request-response round
	private static void feedback(CommandAPDU command, ResponseAPDU response) {
		out(command);
		in(response);
	}

	// feedback/debug: PCD --> PICC
	private static void out(CommandAPDU command) {
		System.out.println(">> " + Dump.hex(command.getBytes(), true)
				+ " (" + Command.getCommand(command.getINS()) + ")");
	}

	// feedback/debug: PICC --> PCD
	private static void in(ResponseAPDU response) {
		System.out.println("<< " + Dump.hex(response.getBytes(), true)
				+ " (" + Response.getResponse(response.getSW2()) + ")");
	}

	// rotate the array one byte to the left
	private static byte[] rotateLeft(byte[] a) {
		byte[] ret = new byte[a.length];

		System.arraycopy(a, 1, ret, 0, a.length - 1);
		ret[a.length - 1] = a[0];

		return ret;
	}

	/**
	 * Get the status code of the response of the previous command sent to the PICC.
	 * 
	 * @return	the status code of the response
	 */
	public int getCode() {
		return code;
	}

	public String getCodeDesc() {
		return Response.getResponse(code).toString();
	}
	
	/**
	 * Given a Triple DES key, finds out the version.
	 * The key version is based on the parity bits taken from the
	 * first 8 bytes of the key.
	 * <p>
	 * [a,x,x,x,x,x,x,x,b]: byte a contains MSBit and byte b contains LSBit.
	 * 
	 * @param aKey	the key (8/16/24 bytes)
	 * @return		the key version based on parity bits
	 */
	public byte findKeyVersion(byte[] aKey) {
		if (aKey.length < 8)
			return FAKE_NO;
		
		byte version = 0;
		
		for (int i = 0; i < 8; i++) {
			version |= (aKey[i] & 0x01) << (7 - i);
		}
		
		return version;
	}

	/**
	 * Checks whether a 16-byte key is a 3DES key.
	 * <p>
	 * Some 3DES keys may actually be DES keys because the LSBit of
	 * each byte is used for key versioning by MDF. A 16-byte key is
	 * also a DES key if the first half of the key is equal to the second.
	 * 
	 * @param key	the 16-byte 3DES key to check
	 * @return		<code>true</code> if the key is a 3DES key
	 */
	public static boolean isKey3DES(byte[] key) {
		if (key.length != 16)
			return false;
		byte[] tmpKey = Arrays.copyOfRange(key, 0, key.length);
		setKeyVersion(tmpKey, 0, tmpKey.length, (byte) 0x00);
		for (int i = 0; i < 8; i++)
			if (tmpKey[i] != tmpKey[i + 8])
				return true;
		return false;
	}

	/**
	 * Validates a key according with its type.
	 * 
	 * @param key	the key
	 * @param type	the type
	 * @return		{@code true} if the key matches the type,
	 * 				{@code false} otherwise
	 */
	public static boolean validateKey(byte[] key, KeyType type) {
		if (type == KeyType.DES && (key.length != 8)
				|| type == KeyType.TDES && (key.length != 16 || !isKey3DES(key))
				|| type == KeyType.TKTDES && key.length != 24
				|| type == KeyType.AES && key.length != 16) {
			System.err.println(String.format("Key validation failed: length is %d and type is %s", key.length, type));
			return false;
		}
		return true;
	}

	/**
	 * Parse the output of {@linkplain #getVersion()} into a human-readable form.
	 * 
	 * @param getVersion	the output of {@linkplain #getVersion()} ({@code <> null})
	 * @return				human-readable form of {@linkplain #getVersion()}
	 */
	public static String parseGetVersion(byte[] getVersion) {
		StringBuilder sb = new StringBuilder();

		// hardware info
		sb.append("Hardware info\n");
		sb.append("       vendor:\t" + String.format("0x%02x", getVersion[0]));
		sb.append((getVersion[0] == 0x04 ? "            NXP\n" : '\n'));
		sb.append(" type/subtype:\t" + String.format("0x%02x/0x%02x\t", getVersion[1], getVersion[2]) + '\n');
		sb.append("      version:\t" + String.format("%d", getVersion[3]) + '.' + String.format("%d", getVersion[4])  + '\n');
		int exp = (getVersion[5] >>> 1);
		sb.append(" storage size:\t" + (int) Math.pow(2, exp));
		//sb.append((getVersion[5] & 0b1) == 0 ? " bytes\n" : " to " + (int) Math.pow(2, (exp) + 1) + " bytes\n");//1.7 only
		sb.append((getVersion[5] & 0x01) == 0 ? " bytes\n" : " to " + (int) Math.pow(2, (exp) + 1) + " bytes\n");
		sb.append("     protocol:\t" + String.format("0x%02x", getVersion[6]));
		sb.append(getVersion[6] == 0x05 ? "            ISO 14443-3 and ISO 14443-4\n" : '\n');

		// software info
		sb.append("\nSoftware info\n");
		sb.append("       vendor:\t" + String.format("0x%02x", getVersion[7]));
		sb.append((getVersion[7] == 0x04 ? "            NXP\n" : '\n'));
		sb.append(" type/subtype:\t" + String.format("0x%02x/0x%02x\t", getVersion[8], getVersion[9]) + '\n');
		sb.append("      version:\t" + String.format("%d", getVersion[10]) + '.' + String.format("%d", getVersion[11])  + '\n');
		exp = (getVersion[12] >>> 1);
		sb.append(" storage size:\t" + (int) Math.pow(2, exp));
		sb.append((getVersion[12] & 0x01) == 0 ? " bytes\n" : " to " + (int) Math.pow(2, (exp) + 1) + " bytes\n");
		sb.append("     protocol:\t" + String.format("0x%02x", getVersion[13]));
		sb.append(getVersion[13] == 0x05 ? "            ISO 14443-3 and ISO 14443-4\n" : '\n');

		// other info
		sb.append("\n batch number:\t" + Dump.hex(Arrays.copyOfRange(getVersion, 21, 21 + 5)) + '\n');
		sb.append("          UID:\t" + Dump.hex(Arrays.copyOfRange(getVersion, 14, 14 + 7)) + '\n');
		sb.append(String.format("   production:\tweek 0x%02x, year 0x%02x  ???", getVersion[22], getVersion[23]));

		return sb.toString();
	}
	
	//dump(check history)

	@Override
	public String toString() {
		//return super.toString();
		byte[] ret = getVersion();
		return ret == null ? "toString failed" : parseGetVersion(getVersion());
	}

	/** Command codes for APDUs sent from the PCD to the PICC. */
	public enum Command {

		// security-level
		AUTHENTICATE_DES_2K3DES		(0x0A),
		AUTHENTICATE_3K3DES			(0x1A),
		AUTHENTICATE_AES			(0xAA),
		CHANGE_KEY_SETTINGS			(0x54),
		SET_CONFIGURATION			(0x5C),
		CHANGE_KEY					(0xC4),
		GET_KEY_VERSION				(0x64),

		// PICC level
		CREATE_APPLICATION			(0xCA),
		DELETE_APPLICATION			(0xDA),
		GET_APPLICATIONS_IDS		(0x6A),
		FREE_MEMORY					(0x6E),
		GET_DF_NAMES				(0x6D),
		GET_KEY_SETTINGS			(0x45),
		SELECT_APPLICATION			(0x5A),
		FORMAT_PICC					(0xFC),
		GET_VERSION					(0x60),
		GET_CARD_UID				(0x51),

		// application level
		GET_FILE_IDS				(0x6F),
		GET_FILE_SETTINGS			(0xF5),
		CHANGE_FILE_SETTINGS		(0x5F),
		CREATE_STD_DATA_FILE		(0xCD),
		CREATE_BACKUP_DATA_FILE		(0xCB),
		CREATE_VALUE_FILE			(0xCC),
		CREATE_LINEAR_RECORD_FILE	(0xC1),
		CREATE_CYCLIC_RECORD_FILE	(0xC0),
		DELETE_FILE					(0xDF),

		// file level
		READ_DATA					(0xBD),
		WRITE_DATA					(0x3D),
		GET_VALUE					(0x6C),
		CREDIT						(0x0C),
		DEBIT						(0xDC),
		LIMITED_CREDIT				(0x1C),
		WRITE_RECORDS				(0x3B),
		READ_RECORDS				(0xBB),
		CLEAR_RECORD_FILE			(0xEB),
		COMMIT_TRANSACTION			(0xC7),
		ABORT_TRANSACTION			(0xA7),

		//TODO 9.1-2 section commands from SDS missing; other auth methods as well (e.g. AES)
		MORE						(0xAF),
		UNKNOWN_COMMAND				(1001);

		private int code;

		private Command(int code) {
			this.code = code;
		}

		private int getCode() {
			return code;
		}

		private static Command getCommand(int code) {
			for (Command c : Command.values())
				if (code == c.getCode())
					return c;
			return UNKNOWN_COMMAND;
		}

	}

	/** Status and error codes. */
	public enum Response {
		OPERATION_OK				(0x00),
		NO_CHANGES					(0x0C),
		OUT_OF_EEPROM_ERROR			(0x0E),
		ILLEGAL_COMMAND_CODE		(0x1C),
		INTEGRITY_ERROR				(0x1E),
		NO_SUCH_KEY					(0x40),
		LENGTH_ERROR				(0x7E),
		PERMISSION_DENIED			(0x9D),

		/** A parameter has an invalid value. */
		PARAMETER_ERROR				(0x9E),

		APPLICATION_NOT_FOUND		(0xA0),
		APPLICATION_INTEGRITY_ERROR	(0xA1),

		/** Current authentication status does not allow the requested command. */
		AUTHENTICATION_ERROR		(0xAE),

		ADDITIONAL_FRAME			(0xAF),
		BOUNDARY_ERROR				(0xBE),
		PICC_INTEGRITY_ERROR		(0xC1),

		/** Previous command was incomplete. Not all frames were read. */
		COMMAND_ABORTED				(0xCA),

		PICC_DISABLED_ERROR			(0xCD),

		/** Maximum number of applications reached. */
		COUNT_ERROR					(0xCE),

		DUPLICATE_ERROR				(0xDE),
		EEPROM_ERROR				(0xEE),
		FILE_NOT_FOUND				(0xF0),
		FILE_INTEGRITY_ERROR		(0xF1),

		/** Card sent back the wrong nonce. */
		COMPROMISED_PCD				(1002),

		// nfcjlib custom codes
		WRONG_ARGUMENT				(1001),
		UNKNOWN_CODE				(2013);

		private final int code;

		private Response(int code) {
			this.code = code;
		}

		private int getCode() {
			return this.code;
		}

		private static Response getResponse(int code) {
			for (Response s : Response.values())
				if (code == s.getCode())
					return s;
			return UNKNOWN_CODE;
		}

	}

	/**
	 * File types of applications.
	 */
	public enum FileType {
		STANDARD_DATA_FILE	(0),
		BACKUP_DATA_FILE	(1),
		VALUE_FILE			(2),
		LINEAR_RECORD_FILE	(3),
		CYCLIC_RECORD_FILE	(4),
		UNKNOWN_FILE_TYPE	(0xFF);

		private final int code;
		private FileType(int code) {
			this.code = code;
		}
		private int getCode() {
			return this.code;
		}
		private static FileType getStatus(int code) {
			for (FileType ft : FileType.values())
				if (code == ft.getCode())
					return ft;
			return UNKNOWN_FILE_TYPE;
		}
	}

	/** Ciphers supported by DESFire EV1. */
	public enum KeyType {
		DES,
		TDES,
		TKTDES,
		AES;
	}

	/**
	 * The communication settings between PCD and PICC.
	 * The communication mode can be plain text, plain text with MAC/CMAC, or
	 * plain text with CRC and full encryption.
	 */
	private enum CommunicationSetting {
		PLAIN,
		MACED,
		ENCIPHERED;
	}

	/**
	 * DES/3DES mode of operation.
	 * @see nfcjlib.core.DESFireEV1#decryptDES(byte[], byte[], DESMode)
	 */
	private enum DESMode {
		SEND_MODE,
		RECEIVE_MODE;
	}

	/*private enum AccessRight {
		READ,
		WRITE,
		READ_WRITE,
		CHANGE;
	}*/

	/**
	 * Authentication done in two steps.
	 * Useful when actions have to be taken in between the message exchanges.
	 * Call start to execute the first step and end to execute the second step.
	 * <p>
	 * randA: random number A<br>
	 * randB: random number B<br>
	 * randAr: random number A rotated<br>
	 * randAre: random number A rotated and enciphered<br>
	 * randBr: random number B rotated<br>
	 * randABre: random numbers concatenated with B rotated and both enciphered<br>
	 * randBe: random number B enciphered
	 * 
	 * @author Daniel Andrade
	 * @version 1.0
	 *
	 */
	public static class RawAuthentication {

		/**
		 * Run all the methods in {@code RawAuthentication} to perform the
		 * authentication with the smart card in one go.
		 * <p>
		 * Demonstrates how the methods relate to each other.
		 * 
		 * @param key		the shared secret key
		 * @param keyNo		the key number
		 * @param type		the key type
		 * @return			the session key on success, or {@code null} on error
		 */
		public static byte[] runAll(DESFireEV1 desfire, byte[] key, byte keyNo, KeyType type) {
			byte[] randBe = start(desfire, keyNo, type);
			if (randBe == null)
				return null;

			int randLen = randBe.length;

			byte[] randB = decipherRandB(key, type, randBe);
			if (randB == null)
				return null;

			byte[] randBr = rotateRandB(randB);

			byte[] randA = generateRandA(randLen);

			byte[] randABre = encipherAB(key, type, randBe, randLen, randA, randBr);
			if (randABre == null)
				return null;

			byte[] randAre = exchangeSecondMsg(desfire, randABre);
			if (randAre == null)
				return null;

			byte[] randArCard = decipherRandAre(key, type, randABre, randAre);
			if (randArCard == null)
				return null;

			byte[] randArLocal = rotateRandA(randA);

			if (!checkRandomA(randArCard, randArLocal))
				return null;

			return end(randA, randB, type);
		}

		/**
		 * Initialize the authentication process.
		 * The smart card will return the enciphered random number B.
		 * 
		 * @param keyNo		the key number
		 * @param type		the type of the secret key
		 * @return			the enciphered random number B, or {@code null} on error
		 */
		public static byte[] start(DESFireEV1 desfire, byte keyNo, KeyType type) {
			byte[] apdu = new byte[7];
			apdu[0] = (byte) 0x90;
			switch (type) {
			case DES:
			case TDES:
				apdu[1] = (byte) Command.AUTHENTICATE_DES_2K3DES.getCode();
				break;
			case TKTDES:
				apdu[1] = (byte) Command.AUTHENTICATE_3K3DES.getCode();
				break;
			case AES:
				apdu[1] = (byte) Command.AUTHENTICATE_AES.getCode();
				break;
			default:
				assert false : type;
			}
			apdu[4] = 0x01;
			apdu[5] = keyNo;

			// message exchange with the smart card
			CommandAPDU command = new CommandAPDU(apdu);
			ResponseAPDU response = desfire.transmit(command);
			feedback(command, response);

			return response.getSW2() != 0xAF ? null : response.getData();
		}

		/**
		 * Decipher the random number B.
		 * 
		 * @param key		the shared secret key
		 * @param type		the type of key
		 * @param randBe	the enciphered random number B
		 * @return			the deciphered random number B
		 */
		public static byte[] decipherRandB(byte[] key, KeyType type, byte[] randBe) {
			final byte[] iv0 = type == KeyType.AES ? new byte[16] : new byte[8];

			return recv(key, randBe, type, iv0);
		}

		/**
		 * Rotate the random number B.
		 * 
		 * @param randB		the random number B
		 * @return			the rotated random number B
		 */
		public static byte[] rotateRandB(byte[] randB) {
			return rotateLeft(randB);
		}

		/**
		 * Generate a random number A.
		 * 
		 * @param randLen	the same length as the random number B
		 * @return			the random number A
		 */
		public static byte[] generateRandA(int randLen) {
			byte[] randA = new byte[randLen];
			SecureRandom g = new SecureRandom();
			g.nextBytes(randA);

			return randA;
		}

		/**
		 * Concatenate the random number A with the rotated random number B.
		 * Encipher.
		 * 
		 * @param key		the shared secret key
		 * @param type		the type of key
		 * @param randBe	the enciphered random number B
		 * @param randLen	the length of the random numbers
		 * @param randA		the random number A
		 * @param randBr	the rotated random number B
		 * @return			the concatenated and enciphered random numbers A and B, with the latter rotated
		 */
		public static byte[] encipherAB(byte[] key, KeyType type, byte[] randBe,
				int randLen, byte[] randA, byte[] randBr) {
			final byte[] iv0 = type == KeyType.AES ? new byte[16] : new byte[8];

			byte[] plaintext = new byte[randLen + randLen];
			System.arraycopy(randA, 0, plaintext, 0, randA.length);
			System.arraycopy(randBr, 0, plaintext, randA.length, randBr.length);
			byte[] iv1 = Arrays.copyOfRange(randBe, randBe.length - iv0.length, randBe.length);

			return send(key, plaintext, type, iv1);
		}
		
		public static byte[] packRandA(byte[] key, KeyType type, byte[] randABre, byte[] randA) {
			final byte[] iv0 = type == KeyType.AES ? new byte[16] : new byte[8];
			byte[] iv1 = Arrays.copyOfRange(randABre, randABre.length - iv0.length, randABre.length);
			
			byte[] randAr = rotateLeft(randA);
			
			return send(key, randAr, type, iv1);
		}

		/**
		 * Second message exchange with the smart card.
		 * @param randABre	the ciphered <code>randA||randBr</code>
		 * @return			the enciphered rotated random number A, or {@code null} otherwise 
		 */
		public static byte[] exchangeSecondMsg(DESFireEV1 desfire, byte[] randABre) {
			byte[] apdu = new byte[5 + randABre.length + 1];
			apdu[0] = (byte) 0x90;
			apdu[1] = (byte) 0xAF;
			apdu[4] = (byte) randABre.length;	
			System.arraycopy(randABre, 0, apdu, 5, randABre.length);

			CommandAPDU command = new CommandAPDU(apdu);
			ResponseAPDU response = desfire.transmit(command);
			feedback(command, response);

			return response.getSW2() != 0x00 ? null : response.getData();
		}

		/**
		 * Decipher the rotated random number A, received
		 * during the second message exchange with the smart card.
		 * 
		 * @param key		the shared secret key
		 * @param type		the key type
		 * @param randABre	the concatenated and enciphered random numbers with B rotated
		 * @param randAre	the enciphered and rotated random number A
		 * @return			the random number A
		 */
		public static byte[] decipherRandAre(byte[] key, KeyType type, byte[] randABre, byte[] randAre) {
			final byte[] iv0 = type == KeyType.AES ? new byte[16] : new byte[8];

			byte[] iv2 = Arrays.copyOfRange(randABre, randABre.length - iv0.length, randABre.length);

			return recv(key, randAre, type, iv2);

		}

		/**
		 * Rotate the random number A.
		 * 
		 * @param randA	the random number A
		 * @return		the rotated number A
		 */
		public static byte[] rotateRandA(byte[] randA) {
			return rotateLeft(randA);
		}


		/**
		 * Verify if two random numbers match.
		 * 
		 * @param rand1	the first random number
		 * @param rand2	the second random number
		 * @return		{@code true if the random numbers are the same}
		 */
		public static boolean checkRandomA(byte[] rand1, byte[] rand2) {
			for (int i = 0; i < rand1.length; i++)
				if (rand2[i] != rand1[i])
					return false;

			return true;
		}

		/**
		 * End the authentication protocol by generating the session key.
		 * 
		 * @param randA		the random number A
		 * @param randB		the random number B
		 * @param type		the type of key
		 * @return			the session key
		 */
		public static byte[] end(byte[] randA, byte[] randB, KeyType type) {
			return generateSessionKey(randA, randB, type);
		}

	}

}