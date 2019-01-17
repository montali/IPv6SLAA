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

package test;


import java.io.IOException;
import java.net.NetworkInterface;
import java.util.Enumeration;

import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;
import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.analyzer.LibpcapSniffer;
import it.unipr.netsec.ipstack.analyzer.ProtocolAnalyzer;
import it.unipr.netsec.ipstack.analyzer.Sniffer;
import it.unipr.netsec.ipstack.analyzer.SnifferListener;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.rawsocket.ethernet.RawEthInterface;


/** It captures and analyzes packets received by one or more network interfaces.
  */
public class TcpDump {
	
	/** Verbose mode */
	static boolean VERBOSE=false;
	
	/** Prints a packet dump.
	 * @param pkt the packet */
	public static void printPacketDump(Packet pkt) {
		printPacketDump(pkt,null,false);
	}

	/** Prints a packet dump.
	 * @param pkt the packet
	 * @param ni_id the interface identifier; if not <i>null</i> it is included in the dump */
	public static void printPacketDump(Packet pkt, String ni_id) {
		printPacketDump(pkt,ni_id,false);
	}

	/** Prints a packet dump.
	 * @param pkt the packet
	 * @param ni_id the interface identifier; if not <i>null</i> it is included in the dump
	 * @param no_ssh whether to skip SSH packets (TCP port 22) */
	private static void printPacketDump(Packet pkt, String ni_id, boolean no_ssh) {
		String packet_info=ProtocolAnalyzer.exploreInner(pkt).toString();
		if (no_ssh && packet_info.indexOf(":22 ")>=0) return;
		// else	print the packet
		StringBuffer sb=new StringBuffer();
		sb.append(DateFormat.formatHHmmssSSS(Clock.getDefaultClock().currentTimeMillis())).append(" ");
		if (ni_id!=null) sb.append("[").append(ni_id).append("] ");
		sb.append(packet_info);
		System.out.println(sb.toString());
	}

		
	/** The main method. 
	 * @throws IOException */
	public static void main(String[] args) throws IOException {
		
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		VERBOSE=flags.getBoolean("-v","runs in verbose mode");
		final String eth_name=flags.getString(null,"<interface>",null,"network interface");
		final boolean no_ssh=flags.getBoolean("-nossh","suppresses output for ssh packets (TCP port 22)");
		final boolean ni_id=flags.getBoolean("-niid","prints the interface identifier");
		String out_file=flags.getString("-out","<file>",null,"writes the trace to the given file");

		if (help || eth_name==null || flags.size()>0) {
			System.out.println(flags.toUsageString(TcpDump.class.getSimpleName()));
			System.out.println(Flags.TAB1+"Parameter <interface> must be any of:");
			for (Enumeration<NetworkInterface> i=NetworkInterface.getNetworkInterfaces(); i.hasMoreElements(); ) {
				NetworkInterface ni=i.nextElement();
				System.out.println(Flags.TAB2+ni.getName()+" ("+ni.getDisplayName()+")");
			}
			System.exit(0);			
		}
		
		if (VERBOSE) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			//RawEthInterface.DEBUG=true;
		}
		
		RawEthInterface ni=new RawEthInterface(eth_name);
		if (VERBOSE) {
			System.out.println("Listenning on interface "+ni.getAddresses()[0]);
		}
		
		//new Sniffer(ni,(sniffer, ni, pkt)->printPacketDump(ni_id?ni:null,pkt,no_ssh));
		new Sniffer(ni,new SnifferListener() {
			@Override
			public void onPacket(Sniffer sniffer, NetInterface ni, Packet pkt) {
				printPacketDump(pkt,ni_id?ni.getName():null,no_ssh);
			}
		});

		if (out_file!=null) {
			new LibpcapSniffer(ni,out_file).skipSSH(no_ssh);
		}
	}
}
