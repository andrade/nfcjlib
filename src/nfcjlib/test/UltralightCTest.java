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

import nfcjlib.core.UltralightC;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class UltralightCTest {

	private UltralightC muc;

	@BeforeClass
	public static void setUpOnce() {
		byte[] ret;

		UltralightC ultralight = new UltralightC();
		assumeThat(ultralight.connect(), is(true));
		assumeThat(ultralight.authenticate(new byte[16]), is(true));

		// lock bytes cleared?
		ret = ultralight.read(2);
		assumeThat(ret, is(not(nullValue())));
		assumeThat(ret.length, is(4));
		assumeThat(ret[2], is((byte) 0x00));
		assumeThat(ret[3], is((byte) 0x00));
		ret = ultralight.read(40);
		assumeThat(ret, is(not(nullValue())));
		assumeThat(ret.length, is(4));
		assumeThat(ret[0], is((byte) 0x00));
		assumeThat(ret[1], is((byte) 0x00));

		// auth0 >= 30h?
		ret = ultralight.read(42);
		assumeThat(ret, is(not(nullValue())));
		assumeThat(ret.length, is(4));
		assumeThat(ret[0] >= 0x30, is(true));

		assumeThat(ultralight.disconnect(), is(true));
	}

	@Before
	public void setUp() {
		muc = new UltralightC();
		assumeThat(muc.connect(), is(true));
	}

	//900
	@Test
	public void testAuthenticate0() {
		assertThat(muc.authenticate(new byte[16]), is(true));
	}

	//901
	@Test
	public void testAuthenticate1() {
		assertThat(muc.authenticate(new byte[] {
				0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
				0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00}), is(true));
	}

	//902
	@Test
	public void testAuthenticate2() {
		byte[] newSecretKey = new byte[] {
				0x04, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x02, 0x08,
				0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x00
		};
		assertThat(muc.changeSecretKey(newSecretKey), is(true));

		// the new key only becomes active after reconnecting
		assumeThat(muc.disconnect(), is(true));
		assumeThat(muc.connect(), is(true));

		assertThat(muc.authenticate(newSecretKey), is(true));
	}

	//903
	@Test
	public void testAuthenticate3() {
		byte[] newSecretKey = new byte[] {
				0x04, 0x00, 0x00, 0x00, 0x3B, 0x00, 0x02, 0x08,
				0x00, 0x11, 0x01, 0x4F, 0x00, 0x00, 0x00, 0x43
		};
		assertThat(muc.changeSecretKey(newSecretKey), is(true));

		// the new key only becomes active after reconnecting
		assumeThat(muc.disconnect(), is(true));
		assumeThat(muc.connect(), is(true));

		assertThat(muc.authenticate(newSecretKey), is(true));
	}

	//904
	@Test
	public void testAuthenticate4() {
		assertThat(muc.authenticate(new byte[] {
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		}), is(false));
	}

	//905
	@Test
	public void testChangeSecretKey() {
		byte[] newSecretKey = new byte[] {
				0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
		assertThat(muc.changeSecretKey(newSecretKey), is(true));
	}

	//906
	@Test
	public void testUpdate() {
		assertThat(muc.update(5, new byte[4]), is(true));
	}

	//907
	@Test
	public void testRead() {
		byte[] ret = muc.read(6);
		assertThat(ret, is(not(nullValue())));
		assertThat(ret.length, is(4));
	}

	//908
	@Test
	public void testUpdateRead() {
		int page = 16;
		byte[] newData = new byte[] {0x11, 0x22, 0x33, 0x44};
		byte[] ret;

		assertThat(muc.update(page, newData), is(true));
		ret = muc.read(page);
		assertThat(ret, is(not(nullValue())));
		assertThat(ret.length, is(4));
		assertThat(ret[0], is((byte) 0x11));
		assertThat(ret[1], is((byte) 0x22));
		assertThat(ret[2], is((byte) 0x33));
		assertThat(ret[3], is((byte) 0x44));
	}

	//909
	@Test
	public void testUpdate2() {
		assertThat(muc.update(48, new byte[4]), is(false));
	}

	//910
	@Test
	public void testRead2() {
		assertThat(muc.read(48), is(nullValue()));
	}

	@After
	public void tearDown() {
		muc.disconnect();

		UltralightC ultralight = new UltralightC();
		assumeThat(ultralight.connect(), is(true));
		assumeThat(ultralight.changeSecretKey(new byte[16]), is(true));
		assumeThat(ultralight.disconnect(), is(true));
	}

}