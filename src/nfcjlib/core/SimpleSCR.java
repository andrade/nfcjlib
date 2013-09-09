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

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * A simple smart card reader. Uses the Java Smart Card I/O API which
 * communicates with smart cards using ISO/IEC 7816-4 APDUs.
 * 
 * @author	Daniel Andrade
 * @version	9.9.2013, 0.4
 */
public class SimpleSCR {

	private final static String ATR_ULTRALIGHT_C = "3b 8f 80 01 80 4f 0c a0 00 00 03 06 03 00 03 00 00 00 00 68";
	private final static String ATR_DESFIRE_EV1 = "3b 81 80 01 80 80";

	private Card card;
	private CardChannel channel;

	/**
	 * Establishes a connection with a card. The first reader found is used.
	 * 
	 * @return	<code>true</code> on success
	 */
	public boolean connect() {
		CardTerminals cardTerminals = TerminalFactory.getDefault().terminals();

		try {
			CardTerminal terminal = cardTerminals.list().get(0);
			if (!terminal.isCardPresent()) {
				System.out.println("No smart card present on the terminal.");
				return false;
			}

			card = terminal.connect("*");
			channel = card.getBasicChannel();
			System.out.println(channel.getCard().toString());
		} catch (CardException e) {
			e.printStackTrace();
			System.out.println("Is reader connected?");
			return false;
		}

		return true;
	}

	/** Disconnect the connection with the card.
	 * 
	 * @return	<code>true</code> on success
	 */
	public boolean disconnect() {
		try {
			/* Open the disconnect implementation and check L249.
			 * SCardDisconnect(cardId, (reset ? SCARD_LEAVE_CARD : SCARD_RESET_CARD));
			 * Bug?
			 */
			card.disconnect(false);
		} catch (CardException e) {
			e.printStackTrace();
			return false;
		}

		card = null;
		channel = null;

		return true;
	}

	/**
	 * Send a command to the card and return the response.
	 * 
	 * <p>{@linkplain #connect()} should be called beforehand.
	 * 
	 * @param command	the command
	 * @return			the PICC response
	 */
	public byte[] transmit(byte[] command) {
		try {
			ResponseAPDU response = channel.transmit(new CommandAPDU(command));
			return response.getBytes();
		} catch (CardException e) {
			e.printStackTrace();
			return null;
		}
	}

	protected ResponseAPDU transmit(CommandAPDU command) {
		try {
			ResponseAPDU response = channel.transmit(command);
			return response;
		} catch (CardException e) {
			e.printStackTrace();
			return null;
		}
	}

}