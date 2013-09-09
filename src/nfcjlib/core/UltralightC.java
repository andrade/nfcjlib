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

import java.security.SecureRandom;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import nfcjlib.core.util.Dump;
import nfcjlib.core.util.TripleDES;

/**
 * Eases the manipulation of MIFARE Ultralight C smart cards.
 * 
 * <p>TODO: write to OTP (page 3), to lock bits (pages 2 and 40) and
 * manipulate the 16-bit counter. (Can be done w/ a
 * simple update: remove page check at the beginning of the update command.)
 * 
 * @author	Daniel Andrade
 * @version	9.9.2013, 0.4
 */
public class UltralightC extends SimpleSCR {

	/**
	 * Mutual authentication using 3DES.
	 * 
	 * @param myKey	shared secret key: K1||K2 (16 bytes)
	 * @return		{@code true} on success, {@code false} otherwise
	 */
	public boolean authenticate(byte[] myKey) {
		byte[] iv1 = {0, 0, 0, 0, 0, 0, 0, 0};
		byte[] key = new byte[24];

		// prepare key: K1||K2||K1
		System.arraycopy(myKey, 0, key, 0, 16);
		System.arraycopy(myKey, 0, key, 16, 8);

		// message exchange 1
		byte[] auth1 = {(byte) 0xFF, (byte) 0xEF, 0x00, 0x00, 0x02, 0x1A, 0x00};
		byte[] r1 = transmit(auth1);
		feedback(auth1, r1);
		byte af = (byte) 0xAF;
		if (r1[0] != af) {
			return false;
		}

		// extract random B from response
		byte[] encryptedRandB = new byte[8]; // second IV
		System.arraycopy(r1, 1, encryptedRandB, 0, 8);
		byte[] randB = TripleDES.decrypt(iv1, key, encryptedRandB);

		// generate random A
		byte[] randA = new byte[8];
		SecureRandom g = new SecureRandom();
		g.nextBytes(randA);

		// concatenate/encrypt randA||randB'
		byte[] randConcat = new byte[16];
		System.arraycopy(randA, 0, randConcat, 0, 8);
		System.arraycopy(randB, 1, randConcat, 8, 7);
		System.arraycopy(randB, 0, randConcat, 15, 1);
		byte[] encrRands = TripleDES.encrypt(encryptedRandB, key, randConcat);

		// prepare second message
		byte[] auth2 = new byte[22];
		auth2[0] = (byte) 0xFF;
		auth2[1] = (byte) 0xEF;
		auth2[2] = 0x00;
		auth2[3] = 0x00;
		auth2[4] = 0x11;
		auth2[5] = (byte) 0xAF;
		System.arraycopy(encrRands, 0, auth2, 6, 16);

		// message exchange 2
		byte[] r2 = null;
		try {
			r2 = transmit(auth2);
		} catch (IllegalArgumentException e) {
			//FIXME: handle this without the exception?
			System.out.println("wrong auth key?");
			return false;
		}
		feedback(auth2, r2);
		if (r2[0] != 0) {
			return false;
		}

		// verify received randA
		byte[] iv3 = new byte[8];
		System.arraycopy(auth2, 14, iv3, 0, 8);
		byte[] encryptedRandAp = new byte[8];
		System.arraycopy(r2, 1, encryptedRandAp, 0, 8);
		byte[] decryptedRandAp = TripleDES.decrypt(iv3, key, encryptedRandAp);
		byte[] decryptedRandA = new byte[8];
		System.arraycopy(decryptedRandAp, 0, decryptedRandA, 1, 7);
		decryptedRandA[0] = decryptedRandAp[7];
		for (int i = 0; i < 8; i++) {
			if (decryptedRandA[i] != randA[i]) {
				return false;
			}
		}
		//System.out.println(String.format("randA is %s, randB is %s", Dump.hex(randA), Dump.hex(randB)));

		return true;
	}

	public boolean changeSecretKey(byte[] newKey) {
		CommandAPDU command;
		ResponseAPDU response;
		byte[] apdu = new byte[9];
		apdu[0] = (byte) 0xFF;
		apdu[1] = (byte) 0xD6;
		apdu[2] = 0x00;
		apdu[4] = 0x04;

		// update page 44
		apdu[3] = 0x2C;
		apdu[5] = newKey[7];
		apdu[6] = newKey[6];
		apdu[7] = newKey[5];
		apdu[8] = newKey[4];
		command = new CommandAPDU(apdu);
		response = transmit(command);
		feedback(command, response);
		if (response.getSW1() != 0x90 || response.getSW2() != 0x00)
			return false;

		// update page 45
		apdu[3] = 0x2D;
		apdu[5] = newKey[3];
		apdu[6] = newKey[2];
		apdu[7] = newKey[1];
		apdu[8] = newKey[0];
		command = new CommandAPDU(apdu);
		response = transmit(command);
		feedback(command, response);
		if (response.getSW1() != 0x90 || response.getSW2() != 0x00)
			return false;

		// update page 46
		apdu[3] = 0x2E;
		apdu[5] = newKey[15];
		apdu[6] = newKey[14];
		apdu[7] = newKey[13];
		apdu[8] = newKey[12];
		command = new CommandAPDU(apdu);
		response = transmit(command);
		feedback(command, response);
		if (response.getSW1() != 0x90 || response.getSW2() != 0x00)
			return false;

		// update page 47
		apdu[3] = 0x2F;
		apdu[5] = newKey[11];
		apdu[6] = newKey[10];
		apdu[7] = newKey[9];
		apdu[8] = newKey[8];
		command = new CommandAPDU(apdu);
		response = transmit(command);
		feedback(command, response);
		if (response.getSW1() != 0x90 || response.getSW2() != 0x00)
			return false;

		return true;
	}
	
	//public boolean setOtp(int bitN)
	//public boolean setLock0(int bitN)......
	//private setLock(.....general one that other four call
	//public boolean counterInc()
	//private generalwrite to be called by class methods...
	//dump?

	/**
	 * Set the page from which authentication is required. The default is
	 * 48, which means no restriction.
	 * 
	 * <p>For example, if {@code page} is 20 then authentication is
	 * required from page 20 until the end of the memory. Whether it is only
	 * write restricted or read and write restricted depends on auth1.
	 * 
	 * @param page	page number from which authentication is required
	 * @return		<code>true</code> if set successfully
	 */
	public boolean setAuth0(int page) {
		if (page < 0 || page > 48) {
			return false;
		}

		byte[] apdu = new byte[9];
		apdu[0] = (byte) 0xFF;
		apdu[1] = (byte) 0xD6;
		apdu[2] = 0x00;
		apdu[3] = 0x2A;
		apdu[4] = 0x04;
		apdu[5] = (byte) page;
		apdu[6] = apdu[7] = apdu[8] = 0x00;
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);

		if (response.getSW() == (0x90 << 8 | 0x00)) {
			return true;
		}

		return false;
	}

	/**
	 * Set write or read+write restriction on page range set in auth1.
	 * 
	 * @param allowRead	{@code true} to allow read and prevent write,
	 * 					{@code false} to prevent both read and write
	 * @return			{@code true} on success
	 */
	public boolean setAuth1(boolean allowRead) {
		byte[] apdu = new byte[9];
		apdu[0] = (byte) 0xFF;
		apdu[1] = (byte) 0xD6;
		apdu[2] = 0x00;
		apdu[3] = 0x2B;
		apdu[4] = 0x04;
		apdu[6] = apdu[7] = apdu[8] = 0x00;

		if (allowRead) {
			apdu[5] = 0x01;
		} else {
			apdu[5] = 0x00;
		}

		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);

		if (response.getSW() == (0x90 << 8 | 0x00)) {
			return true;
		}

		return false;
	}

	/**
	 * Read a 4-byte page.
	 * 
	 * @param page	the page number to be read (0<=page<=43)
	 * @return		a 4-byte array with the page contents in hexadecimal, or
	 * 				{@code null} on error
	 */
	public byte[] read(int page) {
		if (page < 0 || page > 43) {
			return null;
		}

		byte[] apdu = {(byte) 0xFF, (byte) 0xB0, 0x00, (byte) page, 0x04};
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);
		if (response.getSW() != (0x90 << 8 | 0x00)) {
			return null;
		}

		return response.getData();
	}

	/**
	 * Update a 4-byte user page.
	 * 
	 * @param page	the number of the page to be updated (4<=page<=39)
	 * @param data	a 4-byte array containing the data in hexadecimal
	 * @return		{@code true} on success
	 */
	public boolean update(int page, byte[] data) {
		if (page < 4 || page > 39) {
			// outside of user memory
			return false;
		}

		byte[] apdu = new byte[9];
		apdu[0] = (byte) 0xFF;
		apdu[1] = (byte) 0xD6;
		apdu[2] = 0x00;
		apdu[3] = (byte) page;
		apdu[4] = 0x04;
		System.arraycopy(data, 0, apdu, 5, 4);
		CommandAPDU command = new CommandAPDU(apdu);
		ResponseAPDU response = transmit(command);
		feedback(command, response);
		if (response.getSW() != (0x90 << 8 | 0x00)) {
			return false;
		}

		return true;
	}

	// provide feedback to the user: can be 'disabled' by quoting prints
	private static void feedback(CommandAPDU command, ResponseAPDU response) {
		System.out.println(">> " + Dump.hex(command.getBytes(), true));
		System.out.println("<< " + Dump.hex(response.getBytes(), true));
	}

	// provide feedback to the user: can be 'disabled' by quoting prints
	private static void feedback(byte[] command, byte[] response) {
		System.out.println(">> " + Dump.hex(command, true));
		System.out.println("<< " + Dump.hex(response, true));
	}

}