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


import it.unipr.netsec.nemo.ip.Ip4Host;
import it.unipr.netsec.nemo.ip.Ip4Router;
import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.link.DataLinkInterface;
import it.unipr.netsec.nemo.link.PacketGenerator;
import it.unipr.netsec.nemo.routing.ShortestPathAlgorithm;
import it.unipr.netsec.nemo.routing.sdn.SdnRouting;
import it.unipr.netsec.ipstack.icmp4.PingClient;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Interface;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.udp.UdpLayer;
import it.unipr.netsec.ipstack.udp.UdpPacket;
import it.unipr.netsec.ipstack.util.IpAddressUtils;
import it.unipr.netsec.simulator.scheduler.VirtualClock;

import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;
import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;


/** Routing in very simple IPv4 network with one or two routers.
 */
public class IPv4SimpleRoutingTest {

	/** DataLink bit rate 1Mb/s */
	static long LINK_BIT_RATE=1000000L;

	
	/** IPv4 network with two links and one router.
	 * <p>
	 * In this test, a network is created with 2 hosts (H1 and H2) connected
	 * to two different access links (link1 and link2) interconnected through
	 * an intermediate router R1.
	 * <p>
	 * H1 sends packets to H2.
	 * <p><center>
	 * H1---(link1)---R1---(link2)---H2
	 * </center><p> */
	private static void testSingleRouterNetwork() {
		IpLink link1=new IpLink(LINK_BIT_RATE,new Ip4Prefix("10.1.0.0/16"));
		IpLink link2=new IpLink(LINK_BIT_RATE,new Ip4Prefix("10.2.0.0/16"));
		Ip4Router r1=new Ip4Router(new IpLink[]{link1,link2});
		System.out.println("R1-RT:\n"+r1.getRoutingTable());

		final long start_nanosecs=Clock.getDefaultClock().nanoTime();
		Ip4Host host1=new Ip4Host(link1);		
		System.out.println("H1-RT:\n"+host1.getRoutingTable());
		Ip4Host host2=new Ip4Host(link2) {
			@Override
			protected void processReceivedPacket(NetInterface ni, Packet pkt) {
				System.out.println("Recv: "+pkt);
				System.out.println("total time: "+(Clock.getDefaultClock().nanoTime()-start_nanosecs)/1000+" us");
			}
		};

		Ip4Address dest_addr=host2.getAddress();
		//int proto=253; // for testing
		byte[] udp_payload="test".getBytes();
		Ip4Packet pkt=new UdpPacket(host1.getSourceAddress(dest_addr),0,dest_addr,0,udp_payload).toIp4Packet();
		System.out.println("Send: "+pkt);
		host1.sendPacket(pkt);
		//host1.ping(dst_addr,count,System.out);
	}

	
	/** IPv4 network with three links and two routers.
	 * <p>
	 * In this test, a network is created with two access networks (link1 and link3)
	 * connected to a backbone network (link2) through the two router R1 and R2.
	 * <p>
	 * H1 connected to the fist access network (link1) sends packets to H2 connected to
	 * the second access network (link3). 
	 * <p><center>
	 * H1---(link1)---R1---(link2)---R2---(link3)---H2
	 * </center><p>
	 * @param count number of sent packets */
	private static void testTwoRouterNetwork(int count) {
		IpLink link1=new IpLink(LINK_BIT_RATE,new Ip4Prefix("10.1.0.0/16"));
		IpLink link2=new IpLink(LINK_BIT_RATE,new Ip4Prefix("10.2.0.0/16"));
		IpLink link3=new IpLink(LINK_BIT_RATE,new Ip4Prefix("10.3.0.0/16"));
		
		/*OspfRouting routing=new OspfRouting(ShortestPathAlgorithm.DIJKSTRA);
		Ip4Router r1=new Ip4Router(new IpLink[]{link1,link2},routing);
		Ip4Router r2=new Ip4Router(new IpLink[]{link2,link3},routing);
		routing.updateAllNodes();*/
		Ip4Router r1=new Ip4Router(new IpLink[]{link1,link2});
		Ip4Router r2=new Ip4Router(new IpLink[]{link2,link3});
		r1.getRoutingTable().add(link3.getPrefix(),r2.getNetInterfaces()[0].getAddresses()[0]);
		r2.getRoutingTable().add(link1.getPrefix(),r1.getNetInterfaces()[1].getAddresses()[0]);	
		System.out.println("R1-RT:\n"+r1.getRoutingTable());
		System.out.println("R2-RT:\n"+r2.getRoutingTable());

		Ip4Address r1_addr=(Ip4Address)r1.getNetInterfaces()[0].getAddresses()[0];
		Ip4Address src_addr=(Ip4Address)link1.nextAddressPrefix();
		Ip4Address dst_addr=(Ip4Address)link3.nextAddressPrefix();
		int proto=253; // for testing
		byte[] ip_payload="test".getBytes();
		Ip4Packet pkt=new Ip4Packet(src_addr,dst_addr,proto,ip_payload);
		System.out.println("Sending "+count+" packet"+(count>1?"s":"")+" of size "+pkt.getPacketLength()+"B from host "+src_addr+" to host "+dst_addr+":");
		PacketGenerator pg=new PacketGenerator(link1,src_addr,link3,dst_addr);
		pg.send(pkt,r1_addr,count,0,null);
		System.out.println("Hop-num: "+pg.getHopNumber());
		System.out.println("Recv-pkts: "+pg.getRxCount());
		if (Clock.getDefaultClock() instanceof VirtualClock) {
			System.out.println("Virtual-time: "+DateFormat.formatNanosecs(pg.getVirtualTime()*1000));
			System.out.println("Real-time: "+DateFormat.formatNanosecs(pg.getRealTime()*1000));
		}
		else {
			System.out.println("Time: "+DateFormat.formatNanosecs(pg.getRealTime()*1000));
		}
	}
	
	
	/** IPv4 linear topology with N routers, and two host.
	 * <p>
	 * H1 connected to the fist access network sends packets to H2 connected to
	 * the last access network (link3). 
	 * <p><center>
	 * (link0)-R1-(link1)-R2-(link2)-..-(linkN-2)-R[N-1]-(linkN-1)-H1
	 * </center><p> 
	 * @param n the number of routers
	 * @param count number of ping requests
	 * @param print_routing_tables prints routing tables
	 * @param pg_size if &gt;0, a packet generator is used in place of PING, with the given packet size */
	public static void testLinearNetwork(int n, int count, boolean print_routing_tables, int pg_size) {
		System.out.println("Linear network topology with "+(n+1)+" link"+(n>0?'s':"")+" and "+n+" router"+(n>1?'s':""));
		try {
			Ip4Prefix super_prefix=new Ip4Prefix("10.1.0.0/16");
			
			// create all links
			IpLink[] links=new IpLink[n+1];
			for (int i=0; i<n+1; i++) links[i]=new IpLink(LINK_BIT_RATE,IpAddressUtils.subnet(super_prefix,24,i));
			
			// dynamic routing
			SdnRouting routing=new SdnRouting(ShortestPathAlgorithm.DIJKSTRA);

			// create all routers
			Ip4Router[] routers=new Ip4Router[n];	
			for (int i=0; i<n; i++) {
				routers[i]=new Ip4Router(new IpLink[]{links[i],links[i+1]});
				routers[i].setDynamicRouting(routing);
			}
			
			// update all routing tables
			routing.updateAllNodes();
			if (print_routing_tables) {
				for (int i=0; i<n; i++) {
					System.out.println("R"+(i+1)+"-RT:\n"+routers[i].getRoutingTable());
				}
			}
			
			System.out.println("DataLink bit-rate: "+DateFormat.formatBitRate(LINK_BIT_RATE)+"\n");
			
			if (pg_size<=0) {
				// create H1 and H2
				Ip4Host host1=new Ip4Host(links[0]);
				Ip4Host host2=new Ip4Host(links[n]);
				
				// ping
				System.out.println("From "+host1.getAddress()+":");
				host1.ping(host2.getAddress(),count,System.out);				
			}
			else {
				int proto=253; // for testing
				byte[] payload=new byte[pg_size-20];
				Ip4Address src_addr=(Ip4Address)links[0].nextAddressPrefix();
				Ip4Address dst_addr=(Ip4Address)links[n].nextAddressPrefix();
				Ip4Packet pkt=new Ip4Packet(src_addr,dst_addr,proto,payload);
				System.out.println("Sending "+count+" "+pkt.getPacketLength()+"B packet"+(count>1?"s":"")+" from host "+src_addr+" to host "+dst_addr+":");
				PacketGenerator pg=new PacketGenerator(links[0],src_addr,links[n],dst_addr);
				pg.send(pkt,links[0].getRouters()[0],count,0,null);
				System.out.println("Hop-num: "+pg.getHopNumber());
				System.out.println("Recv-pkts: "+pg.getRxCount());
				if (Clock.getDefaultClock() instanceof VirtualClock) {
					System.out.println("Virtual-time: "+DateFormat.formatNanosecs(pg.getVirtualTime()*1000));
					System.out.println("Real-time: "+DateFormat.formatNanosecs(pg.getRealTime()*1000));
				}
				else {
					System.out.println("Time: "+DateFormat.formatNanosecs(pg.getRealTime()*1000));
				}			
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	
	/** Main method. 
	 * @throws InterruptedException */
	public static void main(String[] args) throws InterruptedException {
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		boolean verbose=flags.getBoolean("-v","verbose mode");
		int n=flags.getInteger("-n","<num>",1,"number ofrouters");
		LINK_BIT_RATE=DateFormat.parseLongKMG(flags.getString("-b","<bit-rate>",String.valueOf(LINK_BIT_RATE),"link bit rate [b/s] (default is "+DateFormat.formatBitRate(LINK_BIT_RATE)+")"));
		int count=flags.getInteger("-c","<count>",3,"number of ping messages");
		boolean print_routing_tables=flags.getBoolean("-r","prints routing tables");
		int packet_generator=flags.getInteger("-g","<size>",-1,"uses a packet generator in place of ping, with the given packet size");
		boolean virtual_time=flags.getBoolean("-t","uses virtual time");
		
		// example:
		//virtual_time=true;
		//n=10;
		//count=4;
		//verbose=true;
		
		if (help) {
			System.out.println(flags.toUsageString(IPv4SimpleRoutingTest.class.getName()));
			return;
		}
		if (verbose) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			//DataLink.DEBUG=true;
			//DataLinkInterface.DEBUG=true;
			Node.DEBUG=true;
			Ip4Interface.DEBUG=true;
			Ip4Layer.DEBUG=true;
			UdpLayer.DEBUG=true;			
		}
		
		Ip4Packet.DEFAULT_TTL=255;
		if (virtual_time) Clock.setDefaultClock(new VirtualClock());

		/*switch (n) {
			case 1 : testSingleRouterNetwork(); break;
			case 2 : testTwoRouterNetwork(count); break;
			default : testLinearNetwork(n,count);
		}*/
		testLinearNetwork(n,count,print_routing_tables,packet_generator);
	}

}
