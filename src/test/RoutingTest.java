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


import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.link.DataLink;
import it.unipr.netsec.nemo.link.Network;
import it.unipr.netsec.nemo.link.NetworkBuilder;
import it.unipr.netsec.nemo.link.PacketGenerator;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.IpPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.udp.UdpPacket;
import it.unipr.netsec.ipstack.util.IpAddressUtils;
import it.unipr.netsec.simulator.scheduler.VirtualClock;

import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;
import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;


/** Routing in IPv4 or IPv6 network with different topologies (Manhattan, tree, etc.).
 */
public class RoutingTest {

	/** Default bit rate [b/s] */
	static long DEFAULT_BIT_RATE=1000000000L;
	//static long DEFAULT_BIT_RATE=0;

	/** Network prefix */
	//static IpPrefix NET_PREFIX4=new Ip4Prefix("172.16.0.0/12");
	static IpPrefix NET_PREFIX4=new Ip4Prefix("10.0.0.0/9");
	static IpPrefix NET_PREFIX6=new Ip6Prefix("fc00::/16");
	
	/** Default UDP payload length */
	//static int DEFAULT_PAYLOAD_LEN=512;
	static int DEFAULT_IP_PAYLOAD_LEN=1000;// -8-(NET_PREFIX instanceof Ip6Prefix? 40 : 20);

	/** Default network type */
	//static String DEFAULT_NETWORK_TYPE="manhattan 4 4";

	/** Default network size */
	//static int DEFAULT_NETWORK_SIZE=16;

	/** Verbose mode */
	static boolean VERBOSE=false;

		
	/** Test with a Manhattan network.
	 * @param type network type (e.g. "linerar", "manhattan", "tree", "tree3", "tree4", etc.)
	 * @param n network size parameter (depends on the type of network)
	 * @param bit_rate link bit-rate
	 * @param net_prefix IP super-network prefix
	 * @param payload_len UDP payload size
	 * @param pkt_num number of sent packets */
	private static void testNetwork(String type, int n, long bit_rate, IpPrefix net_prefix, int payload_len, long pkt_num) {
		Network network;
		if (type.toLowerCase().startsWith("lin")) {
			network=NetworkBuilder.linearIpNetwork(n,bit_rate,net_prefix);
		}
		else
		if (type.toLowerCase().startsWith("man")) {
			//int n=(int)(Math.sqrt(size-1)+1);
			network=NetworkBuilder.manhattanIpNetwork(n,n,bit_rate,net_prefix);
		}
		else
		if (type.toLowerCase().startsWith("tree")) {
			int degree=type.length()>4? Integer.parseInt(type.substring(4)) : 2;
			network=NetworkBuilder.treeIpCoreNetwork(degree,n,bit_rate,net_prefix);
		}
		else throw new RuntimeException("Unknown network type: "+type);
		
		if (VERBOSE) System.out.println("Network: "+network);

		// TX point
		IpLink[] links=(IpLink[])network.getAccessLinks();
		IpLink link1=links[0];
		IpAddress r1_addr=link1.getRouters()[0];
		IpPrefix prefix1=link1.getPrefix();
		IpAddress h1_addr=IpAddressUtils.addressPrefix(prefix1,2);
		if (VERBOSE) System.out.println("Source: h1="+h1_addr+"/"+prefix1.prefixLength()+", gw="+r1_addr);
		//IpAddressPrefix h1_addr=link1.nextAddressPrefix();
		//if (VERBOSE) System.out.println("Source: h1="+h1_addr.toStringWithPrefixLength()+", r1="+r1_addr);
		
		// RX point
		IpLink link2=links[links.length-1];
		IpAddress r2_addr=link2.getRouters()[0]; // not used
		IpPrefix prefix2=link2.getPrefix();
		IpAddress h2_addr=IpAddressUtils.addressPrefix(prefix2,2);
		if (VERBOSE) System.out.println("Target: h2="+h2_addr+"/"+prefix2.prefixLength()+", gw="+r2_addr);
		//IpAddressPrefix h2_addr=link2.nextAddressPrefix();
		//if (VERBOSE) System.out.println("Destination: h2="+h2_addr.toStringWithPrefixLength()+", r2="+r2_addr);

		// sender and receiver
		PacketGenerator pg=new PacketGenerator(link1,h1_addr,link2,h2_addr);

		// packet
		UdpPacket udp_pkt=new UdpPacket(h1_addr,4000,h2_addr,4000,new byte[payload_len]);
		Packet ip_pkt=h1_addr instanceof Ip4Address? udp_pkt.toIp4Packet() : udp_pkt.toIp6Packet();

		pg.send(ip_pkt,r1_addr,pkt_num,0,null);
		System.out.print(""+n
				+'\t'+network.getNodes().length
				+'\t'+((network.getCoreLinks()!=null?network.getCoreLinks().length:0)+(network.getAccessLinks()!=null?network.getAccessLinks().length:0))
				+'\t'+pg.getHopNumber()
				+'\t'+pg.getRxCount()
				+'\t'+ip_pkt.getPacketLength()
				+'\t'+pg.getVirtualTime()
				+'\t'+pg.getRealTime()/1000
				+'\n');
	}
		

	/** Main method. 
	 * @throws InterruptedException */
	public static void main(String[] args) throws InterruptedException {
		Ip4Packet.DEFAULT_TTL=255;
		Clock.setDefaultClock(new VirtualClock());
		
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		VERBOSE=flags.getBoolean("-v","runs in verbose mode");
		long bit_rate=flags.getLong("-b","<bit-rate>",DEFAULT_BIT_RATE,"link bit-rate [b/s]");
		int payload_len=flags.getInteger("-B","<payload-len>",-1,"UDP payload length [byte]");
		long pkt_num=flags.getLong("-c","<pkts>",1,"number of packets");
		int n=flags.getInteger("-n","<size>",4,"network size n (e.g. manhattan nxn or tree height n)");
		int N=flags.getInteger("-N","<size>",n,"maximum network size n");
		String type=flags.getString("-t","<type>","linear","network type (manhattan, linear, tree, tree3, tree4, etc)");
		boolean ipv6=flags.getBoolean("-6","uses an IPv6 network");
		
		if (VERBOSE) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			DataLink.DEBUG=true;
			Node.DEBUG=true;
		}
		
		if (help) {
			System.out.println(flags.toUsageString(RoutingTest.class.getSimpleName()));
			System.out.println();
			System.out.println("By default, it is used an IPv4 linear network with 4 routers, link bit-rate="+DateFormat.formatBitRate(DEFAULT_BIT_RATE)+", and UDP payload size="+(DEFAULT_IP_PAYLOAD_LEN-28)+".");
			return;
		}

		IpPrefix net_prefix=ipv6? NET_PREFIX6 : NET_PREFIX4;
		if (payload_len<0) {
			payload_len=DEFAULT_IP_PAYLOAD_LEN-8-(ipv6? 40 : 20);
		}

		// print recap info
		if (type.toLowerCase().startsWith("lin")) {
			System.out.println("Topology: Linear n");
			System.out.println("Routers: n");
			System.out.println("Links: n+1");
		}
		else
		if (type.toLowerCase().startsWith("man")) {
			System.out.println("Topology: Manhattan nxn");
			System.out.println("Routers: n*n");
			System.out.println("Links: 2n*n+2n");
		}
		else
		if (type.toLowerCase().startsWith("tree")) {
			int degree=type.length()>4? Integer.parseInt(type.substring(4)) : 2;
			System.out.println("Topology: "+degree+"-ary Tree, height=n");
			System.out.println("Routers: ("+degree+"^(n+1)-1)/(n-1)");
			System.out.println("Links: "+degree+"^(n+1)-2+"+degree+"^n");
		}
				
		System.out.println("Bit-rate: "+DateFormat.formatBitRate(bit_rate));
		System.out.println("n\trouters\tlinks\thops\tpkts\tplen[B]\tvt[us]\trt[ms]");

		// run
		for (; n<=N; n++) {
			testNetwork(type,n,bit_rate,net_prefix,payload_len,pkt_num);
		}
	}

}
