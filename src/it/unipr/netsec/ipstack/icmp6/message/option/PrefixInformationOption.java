/*
 * Copyright 2018 NetSec Lab - University of Parma
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author(s):
 * Luca Veltri (luca.veltri@unipr.it)
 */

package it.unipr.netsec.ipstack.icmp6.message.option;


import it.unipr.netsec.ipstack.ip6.Ip6AddressPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;


/** Prefix information option.
 * */
public class PrefixInformationOption extends Icmp6Option {

	/** Creates a new ICMP6 option.
	 * @param o the ICMPv6 option */
	public PrefixInformationOption(Icmp6Option o) {
		super(o);
		checkOptionType();
	}

	/** Creates a new ICMP6 option.
	 * @param pref the prefix */
	public PrefixInformationOption(Ip6AddressPrefix pref) {
		super(TYPE_Prefix_Information,pref.getBytes());
		checkOptionType();
	}
	public PrefixInformationOption(int prefix_len, byte flags, byte[] valid_lifetime, byte[] pref_lifetime, Ip6AddressPrefix pref) {
		super(TYPE_Prefix_Information, getOptionBytes(prefix_len, flags, valid_lifetime, pref_lifetime, pref));
	}
	
	private static byte[] getOptionBytes(int prefix_len, byte flags, byte[] valid_lifetime, byte[] pref_lifetime, Ip6AddressPrefix pref){
		byte[] option_bytes = new byte[30];
		option_bytes[0] = (byte) prefix_len;
		option_bytes[1] = flags;
		System.arraycopy(valid_lifetime, 0, option_bytes, 2, 6);
		System.arraycopy(pref_lifetime, 0, option_bytes, 8, 6);
		System.arraycopy(pref.getBytes(), 0, option_bytes, 14, 16);
		return option_bytes;
	}
	
	public int getPrefixLength () {
		return this.getValue()[0];
	}
	
	public Ip6AddressPrefix getPrefix ()
	{
		byte[] address = new byte[16];
		this.getBytes(address, 16);
		return new Ip6AddressPrefix(address, this.getPrefixLength());
	}
	/** Parses an ICMP6 option.
	 * @param buf buffer containing the option */
	public static PrefixInformationOption parseOption(byte[] buf) {
		return parseOption(buf,0);
	}

	/** Parses an ICMP6 option.
	 * @param buf buffer containing the option
	 * @param off the offset within the buffer */
	public static PrefixInformationOption parseOption(byte[] buf, int off) {
		return new PrefixInformationOption(Icmp6Option.parseOption(buf,off));
	}
	
	/** Checks the correctness of the option type.
	 * @return <i>true</i> if it is correct */
	private void checkOptionType() {
		if (type!=TYPE_Prefix_Information) throw new RuntimeException("ICMP6 option type ("+type+") is not a \"Prefix Information\" ("+TYPE_Prefix_Information+")");
	}
		 
}
