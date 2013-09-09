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
package nfcjlib.test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV1.KeyType;
import nfcjlib.core.util.BitOp;
import nfcjlib.core.util.Dump;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.ParameterSignature;
import org.junit.experimental.theories.ParameterSupplier;
import org.junit.experimental.theories.ParametersSuppliedBy;
import org.junit.experimental.theories.PotentialAssignment;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.experimental.theories.suppliers.TestedOn;
import org.junit.runner.RunWith;

/**
 * FIXME: rewrite header.
 * <p>
 * Test cases for the DESFireEV1 class (MIFARE DESFire EV1).
 * <p>
 * The PICC master key is expected to be of type AES and set to zeros.
 * The card is formatted multiple times during the tests.
 * If all goes well, the card is left with the PICC master key
 * set to AES with a 16-byte key composed by zeros. The PICC master key
 * settings will also be set to 0x0F.
 * <p>
 * Note that not all possible behavior is tested.
 * To limit the total run time for the tests, a simple rule of thumb is
 * followed: roughly 40 methods to test, with each method being tested against
 * the four types of cipher (4 keys). Each test case should run a
 * max of 20 times (both positive and negative tests summed up).
 * This gives around: 4 keys * 40 methods * 20 = 3200 test cases to run.
 * <p>
 * The method at-Before changes the PICC master key to one other key for
 * testing and formats the PICC. The method at-After changes the PICC
 * master key back to AES with 16 bytes cleared. Should one of the test
 * cases fail, this ensures that between test cases the PICC master key is
 * known. Attention: if a test run is stopped before conclusion, the PICC
 * master key may not be AES/zeros but one other key from {@code #keys} or
 * defined within the last test case.
 * <p>
 * Some test cases test multiple behaviors. This avoids some overhead at the
 * expense of an increasing complexity in each test case.
 * May be changed in the future.
 * 
 * @author Daniel Andrade
 */
@RunWith(Theories.class)
public class DESFireEV1Test {

	private final static KeyType defaulttpicc = KeyType.AES;   // default PICC master key: type
	private final static byte[]  defaultkpicc = new byte[16];  // default PICC master key: key
	private final static byte[]  aidpicc      = new byte[3];   // PICC: AID
	private final static byte    knopicc      = 0x00;          // PICC: keyNo.
	
	private DESFireEV1 desfire;
	private KeyType    tpicc;  // current PICC master key: type of key
	private byte[]     kpicc;  // current PICC master key: the secret key
	
	private final static java.util.Random rand = new java.util.Random();
	
	public DESFireEV1Test(Key key) {
		tpicc = key.type;
		kpicc = key.key;
	}
	
	/* All test cases run with each of these keys. (Add new ones if needed.)
	 * Keys are assumed to have all bits cleared, or at least one
	 * key for each cipher is present with all bits cleared.
	 */
	@DataPoints
	public static Key[] keys = new Key[] {
		new Key(KeyType.DES, new byte[] {4,4,4,4,4,4,8,4}),
		new Key(KeyType.TDES, new byte[] {2,2,2,2, 4,4,4,4, 8,8,8,8, 0x0C,0x0C,0x0C,0x0C}),
		new Key(KeyType.TKTDES, new byte[] {2,2,2,2,2,2,2,2, 4,4,4,4,4,4,4,4, 8,8,8,8,8,8,8,8}),
		new Key(KeyType.AES, new byte[] {2,2,2,2, 4,4,4,4, 8,8,8,8, 0x0C,0x0C,0x0C,0x0C})
	};
	
	/** Represents a single key. */
	public static class Key {
		KeyType type;
		byte[] key;
		public Key(KeyType type, byte[] key) {
			this.type = type;
			this.key = key;
		}
	}
	
	/**
	 * Authenticates using the default AES key and
	 * sets the PICC master key settings to 0x0F.
	 * If the default key is incorrect, tests shouldn't (can't) be executed.
	 */
	@BeforeClass
	public static void startAll() {
		System.out.println("------------------------------------------------ @BeforeClass -");
		
		DESFireEV1 desfire = new DESFireEV1();
		assumeTrue(desfire.connect());
		assumeTrue(desfire.selectApplication(aidpicc));
		assertNotNull(desfire.authenticate(defaultkpicc, knopicc, defaulttpicc));
		//TODO set master key settings here to 0x0F. Then on test cases don't need to keep doing it all the time. I'll know when I change it.
		// no need to format here
		assumeTrue(desfire.disconnect());
	}
	
	@Before
	public void start() {
		System.out.println("------------------------------------------------ @Before ------");
		System.out.println("The key type is --" + tpicc + "-- and the secret key is --" + Dump.hex(kpicc) + "--");
		
		desfire = new DESFireEV1();
		assumeTrue(desfire.connect());
		
		// change the PICC master key from AES to key (the next key in keys)
		assumeTrue(desfire.selectApplication(aidpicc));
		assumeNotNull(desfire.authenticate(defaultkpicc, knopicc, defaulttpicc));
		assertTrue(desfire.changeKey(knopicc, tpicc, kpicc, null));
		
		assumeNotNull(desfire.authenticate(kpicc, knopicc, tpicc));
		assertTrue(desfire.formatPICC());
		assumeTrue(desfire.disconnect());

		desfire = new DESFireEV1();
		assumeTrue(desfire.connect());
		System.out.println("------------------------------------------------ @Before done--");
	}

	//reqa
	//wupa
	//cascLvl1
	//cascLvl2
	//halt
	
	//rats
	//pps
	//wtx
	//deselect
	
	@Test
	public void testAuthenticate1() {
		assumeTrue(desfire.selectApplication(aidpicc));
		assertThat(desfire.authenticate(kpicc, knopicc, tpicc), notNullValue());
	}
	
	@Test
	public void testAuthenticate2() {
		byte[] myNewKey = Arrays.copyOf(kpicc, kpicc.length);
		for (int i = 0; i < myNewKey.length; i++) {
			myNewKey[i] |= 0x01;
		}
		
		assumeThat(desfire.selectApplication(aidpicc), is(true));
		assumeThat(desfire.authenticate(kpicc, knopicc, tpicc), notNullValue());
		assumeThat(desfire.changeKey(knopicc, tpicc, myNewKey, null), is(true));
		kpicc = myNewKey;
		
		assertThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));
	}
	
	@Test
	public void testAuthenticate3() {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		
		assertThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
	}
	
	@Test
	public void testAuthenticate4() {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte[] myNewKey = Arrays.copyOf(kpicc, kpicc.length);
		for (int i = 0; i < myNewKey.length; i++) {
			myNewKey[i] |= 0x01;
		}
		byte appKeyNo = 0x00;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, appKeyNo, tpicc), is(notNullValue()));
		assumeThat(desfire.changeKey(appKeyNo, tpicc, myNewKey, null), is(true));
		
		assertThat(desfire.authenticate(myNewKey, appKeyNo, tpicc), is(notNullValue()));
	}
	
	@Test
	public void testAuthenticate5() {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte appKeyNo = 0x02;
		
		assumeThat(newApp(aidapp, false, false, true), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		
		assertThat(desfire.authenticate(kpicc, appKeyNo, tpicc), is(notNullValue()));
	}
	
	@Test
	public void testAuthenticate6() {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte[] myNewKey = Arrays.copyOf(kpicc, kpicc.length);
		for (int i = 0; i < myNewKey.length; i++) {
			myNewKey[i] |= 0x01;
		}
		byte appKeyNo = 0x02;
		
		assumeThat(newApp(aidapp, true, false, true), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		assumeThat(desfire.changeKey(appKeyNo, tpicc, myNewKey, kpicc), is(true));
		
		assertThat(desfire.authenticate(myNewKey, appKeyNo, tpicc), is(notNullValue()));
	}

	//test-changeKsettings
	//test-set-configuration
	
	@Test
	public void testChangeKey1() {
		byte[] originalKey = kpicc;
		byte[] keyWithBitsSet = Arrays.copyOf(kpicc, kpicc.length);
		for (int i = 0; i < keyWithBitsSet.length; i++) {
			keyWithBitsSet[i] |= 0x01;  // set version bit
		}
		
		assumeThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));
		assertThat(desfire.changeKey(knopicc, tpicc, keyWithBitsSet, null), is(true));
		kpicc = keyWithBitsSet;
		assumeThat(desfire.authenticate(keyWithBitsSet, knopicc, tpicc), is(notNullValue()));
		assertThat(desfire.changeKey(knopicc, tpicc, originalKey, null), is(true));
		kpicc = originalKey;
	}
	
	@Test
	public void testChangeKey2() {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte[] keyVersionBitsSet = Arrays.copyOf(kpicc, kpicc.length);
		for (int i = 0; i < keyVersionBitsSet.length; i++) {
			keyVersionBitsSet[i] |= 0x01;  // set version bit
		}
		byte appKeyNo = 0x00;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));

		assumeThat(desfire.authenticate(kpicc, appKeyNo, tpicc), is(notNullValue()));
		assertThat(desfire.changeKey(appKeyNo, tpicc, keyVersionBitsSet, null), is(true));

		assumeThat(desfire.authenticate(keyVersionBitsSet, appKeyNo, tpicc), is(notNullValue()));
		assertThat(desfire.changeKey(appKeyNo, tpicc, kpicc, null), is(true));
	}

	@Test
	public void testChangeKey3() {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte[] keyWVersionBitsSet = Arrays.copyOf(kpicc, kpicc.length);
		for (int i = 0; i < keyWVersionBitsSet.length; i++) {
			keyWVersionBitsSet[i] |= 0x01;  // set version bit
		}
		byte appKeyNo = 0x01;

		assumeThat(newApp(aidapp, true, true, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));

		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		assertThat(desfire.changeKey(appKeyNo, tpicc, keyWVersionBitsSet, kpicc), is(true));

		// no need to re-authenticate because the key changed is != 00: amks=0F
		assertThat(desfire.changeKey(appKeyNo, tpicc, kpicc, keyWVersionBitsSet), is(true));
	}

	//109
	@Test
	public void testGetKeyVersion() {
		byte keyVersion = 0x2A;

		assumeThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));
		assumeThat(desfire.changeKey(knopicc, keyVersion, tpicc, kpicc, null), is(true));

		assertThat(desfire.getKeyVersion(knopicc), is(keyVersion));
	}

	//110
	@Test
	public void testKeySettings1() {
		assumeThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));
		assertThat(desfire.changeKeySettings((byte) 0x0F), is(true));
		byte[] ret = desfire.getKeySettings();
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(2));
		assertThat(ret[0], is((byte) 0x0F));
		assertThat(ret[1], is((byte) 0x01));
	}

	//111
	@Test
	public void testKeySettings2() {
		assumeThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));

		byte[] aidapp = new byte[] {1,1,1};
		assumeThat(newApp(aidapp, true, false, false), is(true));

		desfire.selectApplication(aidapp);
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));

		assertThat(desfire.changeKeySettings((byte) 0x0D), is(true));
		byte[] ret = desfire.getKeySettings();
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(2));
		assertThat(ret[0], is((byte) 0x0D));
	}

	//112
	@Test
	public void testGetVersion() {
		assertThat(desfire.getVersion(), is(notNullValue()));
	}

	//113
	@Test
	public void testGetCardUID() {
		assumeThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));
		assertThat(desfire.getCardUID(), is(notNullValue()));
	}

	//114
	@Test
	public void testFormatMF3ICD81a() {
		assertThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));
		assertTrue(desfire.formatPICC());
		assertTrue(desfire.formatPICC());
	}

	//115
	@Test
	public void testFormatMF3ICD81b() {
		assertFalse(desfire.formatPICC());
	}
	
	//116
	@Test
	public void testFreeMemory() {
		byte[] ret = desfire.freeMemory();
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(3));
	}
	
	@Test
	public void testSelectApplication1() {
		assertTrue(desfire.selectApplication(aidpicc));
	}
	
	@Test
	public void testSelectApplication2() {
		assertFalse(desfire.selectApplication(new byte[] {1,2,3}));
	}
	
	@Test
	public void testCreateApplication1() {
		assertThat(desfire.createApplication(new byte[] {1,2,0}, (byte) 0x0F, (byte) 0x05), is(true));
		assertThat(desfire.createApplication(new byte[] {1,2,4}, (byte) 0x0F, (byte) 0x45), is(true));
		assertThat(desfire.createApplication(new byte[] {1,2,8}, (byte) 0x0F, (byte) 0x85), is(true));
	}
	
	@Test
	public void testCreateApplication2() {
		assertThat(desfire.createApplication(new byte[] {1,2,8}, (byte) 0x0F, (byte) 0x85), is(true));
		assertThat(desfire.createApplication(new byte[] {1,2,8}, (byte) 0x0F, (byte) 0x85), is(false));
	}
	
	//204
	@Test
	public void testDeleteApplication1() {
		byte[] aidapp = new byte[] {3, 4, 5};
		assumeThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));
		assumeThat(desfire.createApplication(aidapp, (byte) 0x0F, (byte) 0x05), is(true));
		assertThat(desfire.deleteApplication(aidapp), is(true));
	}
	
	//205
	@Test
	public void testDeleteApplication2() {
		assumeThat(desfire.authenticate(kpicc, knopicc, tpicc), is(notNullValue()));
		assertThat(desfire.deleteApplication(new byte[] {5, 6, 7}), is(false));
	}
	
	//206
	@Test
	public void testDeleteFile1() {
		byte[] aidapp = new byte[] {0x05, 0x06, 0x07};
		byte fileNo = 0x00;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));

		assumeTrue(desfire.createStdDataFile(new byte[] {fileNo, 0x00, 0x00, 0x00, 0x20, 0, 0}));
		
		assertThat(desfire.getFileIds().length, is(1));
		assertThat(desfire.deleteFile(fileNo), is(true));
		assertThat(desfire.getFileIds().length, is(0));
	}
	
	//207
	@Test
	public void testDeleteFile2() {
		byte[] aidapp = new byte[] {0x05, 0x06, 0x07};
		byte fileNo = 0x00;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));

		assertThat(desfire.deleteFile(fileNo), is(false));
	}

	//208
	@Theory
	public void testGetFileIds() {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		assertThat(desfire.getFileIds().length, is(0));
		for (int i = 0; i < 32; i++) {
			assumeTrue(desfire.createStdDataFile(new byte[] {(byte) i, 0x00, 0x00, 0x00, 0x20, 0, 0}));
			assertThat(desfire.getFileIds().length, is(i + 1));
		}
	}

	@Test
	public void testGetApplicationsIds() {
		assumeTrue(desfire.selectApplication(aidpicc));
		assumeNotNull(desfire.authenticate(kpicc, knopicc, tpicc));
		
		byte[] ret = desfire.getApplicationsIds();
		assertNotNull(ret);
		assertThat(ret.length, is(0));
		
		for (int i = 0; i < 4; i++) {
			for (int j = 1; j <= 7; j++) {
				assumeTrue(desfire.createApplication(new byte[] {(byte) i, (byte) j, 0}, (byte) 0x0F, (byte) 0x01));
				
				ret = desfire.getApplicationsIds();
				assertNotNull(ret);
				assertThat(ret.length, is((i * 7 + j) * 3));
			}
		}
	}
	
	//209
	@Theory
	public void testGetFileSettings1(@TestedOn(ints = {0, 1, 3}) int cs) {
		int fileNo = rand.nextInt(0x1F + 1);
		int ar1 = rand.nextInt(0xFF + 1);
		int ar2 = rand.nextInt(0xFF + 1);
		byte[] aidapp = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
		byte[] ret;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		// standard data file
		assumeTrue(String.format("Creating stdDataFile: fileNo=%02x, ar1=%02x, ar2=%02x", fileNo, ar1, ar2),
				desfire.createStdDataFile(new byte[] {(byte) fileNo, (byte) cs, (byte) ar1, (byte) ar2, 0x30, 0, 0}));
		ret = desfire.getFileSettings(fileNo);
		assertNotNull(ret);
		assertThat(ret.length, is(7));
		assertEquals(ret[1], cs);
		assertThat(ret[2], is((byte) ar1));
		assertThat(ret[3], is((byte) ar2));
	}
	
	//210
	@Test
	public void testGetFileSettings2() {
		byte[] aidapp = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));

		assumeThat(desfire.getFileSettings(0x00), is(nullValue()));
	}
	
	//211
	@Test
	public void testGetFileSettings3() {
		byte fileNo = 0x1C;
		byte cs = 0x01;
		byte ar1 = 0x00;
		byte ar2 = 0x00;
		byte[] aidapp = new byte[] {(byte) 0xA5, (byte) 0x3D, (byte) 0x4F};
		byte[] ret;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		// standard data file
		assumeTrue(desfire.createStdDataFile(new byte[] {fileNo, cs, ar1, ar2, 0x30, 0, 0}));
		assertTrue(desfire.changeFileSettings(fileNo, (byte) 0x03, (byte) 0x01, (byte) 0xEE));
		ret = desfire.getFileSettings(fileNo);
		assertNotNull(ret);
		assertThat(ret.length, is(7));
		assertEquals(ret[1], 0x03);
		assertThat(ret[2], is((byte) 0x01));
		assertThat(ret[3], is((byte) 0xEE));
	}
	
	@Theory
	public void testStdDataFile1(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x00;
		byte fileSizeLSB = 0x41;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, fileSizeLSB, 0, 0};
		assertThat(desfire.createStdDataFile(payload), is(true));
	}
	
	@Theory
	public void testStdDataFile2(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x00;
		byte fileSizeLSB = 0x41;
		byte offset = 2;
		byte[] payload, ret;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, fileSizeLSB, 0, 0};
		assumeThat(desfire.createStdDataFile(payload), is(true));
		
		payload = new byte[] {fileNo, offset, 0, 0, 2, 0, 0, 0x7D, 0x7E};
		assertThat(desfire.writeData(payload), is(true));
		
		ret = desfire.readData(new byte[] {fileNo, 0, 0, 0, 0, 0, 0});
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is((int) fileSizeLSB));
		assertThat((int) ret[offset], is(0x7D));
		assertThat((int) ret[offset + 1], is(0x7E));
	}
	
	@Theory
	public void testStdDataFile3(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x00;
		byte fileSizeLSB = 0x41;
		byte[] payload;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, fileSizeLSB, 0, 0};
		assumeThat(desfire.createStdDataFile(payload), is(true));
		
		payload = new byte[1 + 3 + 3 + (fileSizeLSB + 1)];
		payload[0] = fileNo;
		assertThat(desfire.writeData(payload), is(false));
	}
	
	//400
	@Theory
	public void testBackupDataFile1(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x00;
		byte fileSizeLSB = 0x41;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, fileSizeLSB, 0, 0};
		assertThat(desfire.createBackupDataFile(payload), is(true));
	}
	
	//401
	@Theory
	public void testBackupDataFile2(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x00;
		byte fileSizeLSB1 = 0x41;
		byte fileSizeLSB2 = 0x02;
		int fileLength = fileSizeLSB2 << 8 | fileSizeLSB1;
		byte[] payload, ret;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, fileSizeLSB1, fileSizeLSB2, 0};
		assumeThat(desfire.createBackupDataFile(payload), is(true));
		
		payload = new byte[1 + 3 + 3 + fileLength];
		payload[0] = fileNo;
		payload[4] = fileSizeLSB1;
		payload[5] = fileSizeLSB2;
		payload[1 + 3 + 3] = 0x1A;
		payload[payload.length - 1] = 0x1F;
		assertThat(desfire.writeData(payload), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		ret = desfire.readData(new byte[] {fileNo, 0, 0, 0, 0, 0, 0});
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(fileLength));
		assertThat((int) ret[0], is(0x1A));
		assertThat((int) ret[fileLength - 1], is(0x1F));
	}
	
	/*@Theory
	public void testBackupDataFile3(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x05;
		byte fileSizeLSB = 0x20;
		byte[] payload, ret;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, fileSizeLSB, 0, 0};
		assumeThat(desfire.createBackupDataFile(payload), is(true));
		
		payload = new byte[1 + 3 + 3 + fileSizeLSB];
		payload[0] = fileNo;
		payload[4] = fileSizeLSB;
		payload[7] = 0x2A;
		payload[payload.length - 1] = 0x2F;
		assertThat(desfire.writeData(payload), is(true));
		
		ret = desfire.readData(new byte[] {fileNo, 0, 0, 0, 0, 0, 0});//TODO/FIXME: test fails, why? works fine if switch to Std.
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is((int) fileSizeLSB));
		assertThat((int) ret[0], is(not(0x2A)));
		assertThat((int) ret[fileSizeLSB - 1], is(not(0x2F)));
	}*/
	
	@Theory
	public void testValueFile1(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int value = 250;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(value, payload, 12);
		payload[16] = 1;
		
		assertThat(desfire.createValueFile(payload), is(true));
		assertThat(desfire.getValue(fileNo), is(value));
	}
	
	@Theory
	public void testValueFile2(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int value1 = 250;
		int value2 = 10;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(value1, payload, 12);
		payload[16] = 1;
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assertThat(desfire.credit(fileNo, value2), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.getValue(fileNo), is(value1 + value2));
	}
	
	@Theory
	public void testValueFile3(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int value1 = 250;
		int value2 = 10;
		int value3 = 35;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(value1, payload, 12);
		payload[16] = 1;
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assertThat(desfire.debit(fileNo, value2), is(true));
		assertThat(desfire.debit(fileNo, value3), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.getValue(fileNo), is(value1 - value2 - value3));
	}
	
	//503
	@Theory
	public void testValueFile4(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int value1 = 250;
		int value2 = 10;
		boolean limitedCreditEnabled = true;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(value1, payload, 12);
		payload[16] = (byte) (limitedCreditEnabled ? 1 : 0);
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assumeThat(desfire.debit(fileNo, value2), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.limitedCredit(fileNo, value2), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.getValue(fileNo), is(value1));
	}
	
	@Theory
	public void testValueFile5(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int initialVal = 250;
		int maxVal = 450;
		int value2 = maxVal - initialVal + 1;  // valToIncrease > initial+max: fails
		boolean limitedCreditEnabled = true;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(maxVal, payload, 8);
		BitOp.intToLsb(initialVal, payload, 12);
		payload[16] = (byte) (limitedCreditEnabled ? 1 : 0);
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assertThat(desfire.credit(fileNo, value2), is(false));
	}
	
	@Theory
	public void testValueFile6(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int initialVal = 250;
		int minVal = 100;
		int value2 = initialVal - minVal + 1;;  // valToDecrease > initial-min: fails
		boolean limitedCreditEnabled = true;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(minVal, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(initialVal, payload, 12);
		payload[16] = (byte) (limitedCreditEnabled ? 1 : 0);
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assertThat(desfire.debit(fileNo, value2), is(false));
	}
	
	@Theory
	public void testValueFile7(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int value1 = 250;
		boolean limitedCreditEnabled = true;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(value1, payload, 12);
		payload[16] = (byte) (limitedCreditEnabled ? 1 : 0);
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assumeThat(desfire.debit(fileNo, 5), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		assertThat(desfire.limitedCredit(fileNo, 1), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.limitedCredit(fileNo, 1), is(false));
	}
	
	@Theory
	public void testValueFile8(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int value1 = 250;
		int value2 = 15;
		boolean limitedCreditEnabled = true;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(value1, payload, 12);
		payload[16] = (byte) (limitedCreditEnabled ? 1 : 0);
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assumeThat(desfire.debit(fileNo, value2), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		assertThat(desfire.limitedCredit(fileNo, value2 + 1), is(false));
	}
	
	@Theory
	public void testValueFile9(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {4, 5, 6};
		byte fileNo = 0x00;
		int value1 = 250;
		int value2 = 15;
		boolean limitedCreditEnabled = false;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(value1, payload, 12);
		payload[16] = (byte) (limitedCreditEnabled ? 1 : 0);
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assumeThat(desfire.debit(fileNo, value2), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		assertThat(desfire.limitedCredit(fileNo, value2), is(false));
	}
	
	@Theory
	public void testLinearRecordFile1(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x01;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, 1, 0, 0, 43, 0, 0};
		
		assertThat(desfire.createLinearRecordFile(payload), is(true));
	}
	
	@Theory
	public void testLinearRecordFile2(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x01;
		byte recordSize = 10;
		byte numRecords = 2;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assumeThat(desfire.createLinearRecordFile(payload), is(true));
		
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 3, 0, 0, 0x41, 0x42, 0x43}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.writeRecord(new byte[] {fileNo, 7, 0, 0, 3, 0, 0, 0x51, 0x52, 0x53}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		byte[] ret = desfire.readRecords(new byte[] {fileNo, 0, 0, 0, 0, 0, 0});  // full-read
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(recordSize * numRecords));
	}
	
	@Theory
	public void testLinearRecordFile3(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x01;
		byte recordSize = 10;
		byte numRecords = 5;
		byte readOffset = 1;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assumeThat(desfire.createLinearRecordFile(payload), is(true));
		
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 3, 0, 0, 0x41, 0x42, 0x43}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.writeRecord(new byte[] {fileNo, 7, 0, 0, 3, 0, 0, 0x51, 0x52, 0x53}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		byte[] ret = desfire.readRecords(new byte[] {fileNo, readOffset, 0, 0, 0, 0, 0});
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is((int) recordSize));
	}
	
	@Theory
	public void testLinearRecordFile4(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x01;
		byte recordSize = 10;
		byte numRecords = 5;
		byte readN = 2;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assumeThat(desfire.createLinearRecordFile(payload), is(true));
		
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 3, 0, 0, 0x41, 0x42, 0x43}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.writeRecord(new byte[] {fileNo, 7, 0, 0, 3, 0, 0, 0x51, 0x52, 0x53}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.writeRecord(new byte[] {fileNo, 3, 0, 0, 3, 0, 0, 0x61, 0x62, 0x63}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		byte[] ret = desfire.readRecords(new byte[] {fileNo, 0, 0, 0, readN, 0, 0});
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(recordSize * 2));
	}
	
	@Theory
	public void testLinearRecordFile5(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x01;
		byte recordSize = 2;
		byte numRecords = 5;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assumeThat(desfire.createLinearRecordFile(payload), is(true));
		
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 2, 0, 0, 0x41, 0x42}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		byte[] ret = desfire.readRecords(new byte[] {fileNo, 0, 0, 0, 0, 0, 0});
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(2));
		assertThat((int) ret[0], is(0x41));
		assertThat((int) ret[1], is(0x42));
	}
	
	@Theory
	public void testLinearRecordFile6(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x01, 0x01, 0x01};
		byte fileNo = 0x01;
		byte recordSize = 2;
		byte numRecords = 5;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assumeThat(desfire.createLinearRecordFile(payload), is(true));
		
		assumeThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 2, 0, 0, 0x41, 0x42}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		assertThat(desfire.clearRecordFile(fileNo), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.readRecords(new byte[] {fileNo, 0, 0, 0, 0, 0, 0}), is(nullValue()));
	}
	
	@Theory
	public void testCyclicRecordFile1(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {6, 6, 6};
		byte fileNo = 0x03;
		byte recordSize = 2;
		byte numRecords = 3;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assertThat(desfire.createCyclicRecordFile(payload), is(true));
	}
	
	@Theory
	public void testCyclicRecordFile2(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {6, 6, 6};
		byte fileNo = 0x03;
		byte recordSize = 2;
		byte numRecords = 3;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assumeThat(desfire.createCyclicRecordFile(payload), is(true));
		
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 2, 0, 0, 0x41, 0x42}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 2, 0, 0, 0x51, 0x52}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		byte[] ret = desfire.readRecords(new byte[] {fileNo, 0, 0, 0, 0, 0, 0});
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(recordSize * (numRecords - 1)));
		assertThat((int) ret[0], is(0x41));
		assertThat((int) ret[1], is(0x42));
		assertThat((int) ret[2], is(0x51));
		assertThat((int) ret[3], is(0x52));
	}
	
	@Theory
	public void testCyclicRecordFile3(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {6, 6, 6};
		byte fileNo = 0x03;
		byte recordSize = 1;
		byte numRecords = 3;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assumeThat(desfire.createCyclicRecordFile(payload), is(true));
		
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 1, 0, 0, 0x1A}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 1, 0, 0, 0x1B}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 1, 0, 0, 0x1C}), is(true));
		assumeThat(desfire.commitTransaction(), is(true));
		
		byte[] ret = desfire.readRecords(new byte[] {fileNo, 0, 0, 0, 0, 0, 0});
		assertThat(ret, is(notNullValue()));
		assertThat(ret.length, is(recordSize * (numRecords - 1)));
		assertThat((int) ret[0], is(0x1B));
		assertThat((int) ret[1], is(0x1C));
	}
	
	@Theory
	public void testCyclicRecordFile4(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {6, 6, 6};
		byte fileNo = 0x03;
		byte recordSize = 1;
		byte numRecords = 7;

		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[] {fileNo, (byte) cs, 0x02, 0x22, recordSize, 0, 0, numRecords, 0, 0};
		assumeThat(desfire.createCyclicRecordFile(payload), is(true));
		
		assertThat(desfire.writeRecord(new byte[] {fileNo, 0, 0, 0, 2, 0, 0, 0x1A, 0x1B}), is(false));
	}
	
	//800
	@Theory
	public void testCommitTransaction(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x04, 0x05, 0x06};
		byte fileNo = 0x00;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(245, payload, 12);
		payload[16] = 0x01;
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assumeThat(desfire.credit(fileNo, 5), is(true));
		assertThat(desfire.commitTransaction(), is(true));
		assertThat(desfire.getValue(fileNo), is(245 + 5));
	}
	
	//801
	@Theory
	public void testAbortTransaction(@TestedOn(ints = {0, 1, 3}) int cs) {
		byte[] aidapp = new byte[] {0x04, 0x05, 0x06};
		byte fileNo = 0x00;
		
		assumeThat(newApp(aidapp, true, false, false), is(true));
		assumeThat(desfire.selectApplication(aidapp), is(true));
		assumeThat(desfire.authenticate(kpicc, (byte) 0x00, tpicc), is(notNullValue()));
		
		byte[] payload = new byte[17];
		payload[0] = fileNo;
		payload[1] = (byte) cs;
		payload[2] = (byte) 0x00;
		payload[3] = (byte) 0x00;
		BitOp.intToLsb(5, payload, 4);
		BitOp.intToLsb(500, payload, 8);
		BitOp.intToLsb(245, payload, 12);
		payload[16] = 0x01;
		
		assumeThat(desfire.createValueFile(payload), is(true));
		assumeThat(desfire.credit(fileNo, 5), is(true));
		assertThat(desfire.abortTransaction(), is(true));
		assertThat(desfire.getValue(fileNo), is(245));
	}

	@After
	public void end() {
		System.out.println("------------------------------------------------ @After -------");
		assumeTrue(desfire.disconnect());
		
		desfire = new DESFireEV1();
		assumeTrue(desfire.connect());
		
		// change from temporary key to default AES key
		assumeTrue(desfire.selectApplication(aidpicc));
		assumeNotNull(desfire.authenticate(kpicc, knopicc, tpicc));
		assertTrue(desfire.changeKey(knopicc, defaulttpicc, defaultkpicc, null));
		
		assumeTrue(desfire.disconnect());
		
		System.out.println("------------------------------------------------ @After done---");
	}

	@AfterClass
	public static void endAll() {
		System.out.println("------------------------------------------------ @AfterClass --");
		
		DESFireEV1 desfire = new DESFireEV1();
		assumeTrue(desfire.connect());
		assumeTrue(desfire.selectApplication(aidpicc));
		assertNotNull(desfire.authenticate(defaultkpicc, knopicc, defaulttpicc));
		//TODO set master key settings here to 0x0F.
		assumeTrue(desfire.formatPICC());
		assumeTrue(desfire.disconnect());
		System.out.println("done.");
	}
	
	/**
	 * Create a new application using the same type as the PICC master key.
	 * The application master key settings is 0x0F.
	 * The application number of keys is set to 0x0E, 0x4E or 0x8E, according
	 * with the PICC master key type.
	 * Both the application master key and the application key number 1-2 are
	 * changed to the same values as the PICC master key (if booleans are set,
	 * otherwise the default key is left intact).
	 */
	private boolean newApp(byte[] aid, boolean changeKey0, boolean changeKey1, boolean changeKey2) {
		byte amks = 0x0F;
		byte nok = -1;
		byte[] applicationDefaultKey = null;
		KeyType applicationDefaultKeyType = null;
		
		switch (tpicc) {
		case DES:
		case TDES:
			nok = 0x0E;
			applicationDefaultKey = new byte[8];
			applicationDefaultKeyType = KeyType.DES;
			break;
		case TKTDES:
			nok = 0x4E;
			applicationDefaultKey = new byte[24];
			applicationDefaultKeyType = KeyType.TKTDES;
			break;
		case AES:
			nok = (byte) 0x8E;
			applicationDefaultKey = new byte[16];
			applicationDefaultKeyType = KeyType.AES;
			break;
		}
		
		if (!desfire.createApplication(aid, amks, nok))
			return false;
		if (!desfire.selectApplication(aid))
			return false;
		if (null == desfire.authenticate(applicationDefaultKey, (byte) 0x00, applicationDefaultKeyType))
			return false;
		
		if (changeKey2)
			if (!desfire.changeKey((byte) 0x02, tpicc, kpicc, applicationDefaultKey))
				return false;
		
		if (changeKey1)
			if (!desfire.changeKey((byte) 0x01, tpicc, kpicc, applicationDefaultKey))
				return false;
		
		if (changeKey0)
			if (!desfire.changeKey((byte) 0x00, tpicc, kpicc, null))
				return false;

		return true;
	}
	
	// print feedback messages
	private static void out(String msg) {
		System.out.println("[ JUnit4-MDF ]  " + msg);
	}

	/* TO BE DELETED
	@Theory
	public void testCreateApplication(@TestedOn(ints = {1, 1, 1}) int fileNo) {
		byte[] aidapp1 = new byte[] {0x01, 0x02, 0x03};

		assumeTrue(desfire.selectApplication(aidpicc));
		assertTrue(desfire.createApplication(aidapp1, (byte) 0x0F, (byte) fileNo));
	}

	@Theory
	public void testCreateApplication(@AIDs byte[] aid, @TestedOn(ints = {2, 3, 4}) int fileNo) {
		//byte[] aidapp1 = new byte[] {0x01, 0x02, 0x03};

		System.out.println("aid is " + aid.toString());
		assumeTrue(desfire.selectApplication(aidpicc));
		assertTrue(desfire.createApplication(aid, (byte) 0x0F, (byte) fileNo));
	}

	 */

	@Retention(RetentionPolicy.RUNTIME)
	@ParametersSuppliedBy(AuthKeysSupplier.class)
	public @interface AIDs {}

	public static class AuthKeysSupplier extends ParameterSupplier {

		@Override
		public List<PotentialAssignment> getValueSources(ParameterSignature arg0) {
			ArrayList<PotentialAssignment> ret = new ArrayList<PotentialAssignment>();
			ret.add(PotentialAssignment.forValue("aid1", new byte[] {1, 2, 3}));
			ret.add(PotentialAssignment.forValue("aid2", new byte[] {2, 3, 4}));
			ret.add(PotentialAssignment.forValue("aid3", new byte[] {3, 4, 5}));
			return ret;
		}

	}

}