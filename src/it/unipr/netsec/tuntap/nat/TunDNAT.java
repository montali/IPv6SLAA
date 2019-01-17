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

package it.unipr.netsec.tuntap.nat;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4Node;
import it.unipr.netsec.ipstack.nat.DNAT;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.tuntap.ip4.Ip4TunInterface;
import it.unipr.netsec.tuntap.TunSocket;

import java.io.IOException;
import java.util.ArrayList;

import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;


/** Bidirectional D-NAT node, attached to TUN interfaces.
 * It is a special D-NAT (destination NAT) that modifies also the source address.
 * <p>
 * As D-NAT, destination address of new incoming packets is uses as key of a lookup table (the NAT table)
 * for obtaining the pair of new source and destination addresses.
 * <p>
 * Since it performs D-NATting, it works only with static NAT table entries (address mappings),
 * that have to be explicitly set through command-line option <code>-a in-daddr out-saddr out-daddr</code>.
 */
public class TunDNAT {

	
	/** The main method. */
	public static void main(String[] args) throws IOException {
		Flags flags=new Flags(args);
		boolean DEBUG=flags.getBoolean("-debug","debug mode");
		boolean VERBOSE=flags.getBoolean("-v","verbose mode");
		boolean help=flags.getBoolean("-h","prints this message");
		final double err=flags.getDouble("-e","<PER>",0.0,"adds packet error rate, just for testing purpose");
		ArrayList<Ip4TunInterface> tun=new ArrayList<Ip4TunInterface>();
		String[] tun_param=flags.getStringTuple("-i",2,"<tun> <ipaddr/prefix>",null,"tun interface and IPv4 address/prefix length (e.g. '-i tun0 10.1.1.3/24')") ;
		while (tun_param!=null) {
			tun.add(new Ip4TunInterface(new TunSocket(tun_param[0]),new Ip4AddressPrefix(tun_param[1])));
			tun_param=flags.getStringTuple("-i",2,null,null,null);
		}
		if (tun.size()==0) {
			System.out.println(TunDNAT.class.getSimpleName()+": At least one TUN interface has to be configured");
			help=true;
		}
		ArrayList<String[]> nat_mappings=new ArrayList<String[]>();
		String[] nat_param=flags.getStringTuple("-a",3,"<in-daddr> <out-saddr> <out-daddr>",null,"adds a new mapping formed by in-daddr, out-saddr, and out-daddr") ;
		while (nat_param!=null) {
			nat_mappings.add(nat_param);
			nat_param=flags.getStringTuple("-a",3,null,null,null);
		}
		if (help) {
			System.out.println(flags.toUsageString(TunDNAT.class.getSimpleName()));
			System.exit(0);					
		}	
		if (DEBUG) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			Ip4TunInterface.DEBUG=true;
			Node.DEBUG=true;
			Ip4Node.DEBUG=true;
			Ip4Layer.DEBUG=true;							
			DNAT.DEBUG=true;
		}
		if (VERBOSE) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			DNAT.DEBUG=true;
		}
		
		DNAT nat=new DNAT(tun.toArray(new Ip4TunInterface[0]));
		for (String[] nat_map : nat_mappings) {
			nat.add(new Ip4Address(nat_map[0]),new Ip4Address(nat_map[1]),new Ip4Address(nat_map[2]));
		}
	}
	
}
