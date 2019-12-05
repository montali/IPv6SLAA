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

package it.unipr.netsec.ipstack.ip6;


import it.unipr.netsec.ipstack.icmp6.message.option.PrefixInformationOption;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.ethernet.EthLayer;
import it.unipr.netsec.ipstack.ethernet.EthMulticastAddress;
import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.icmp6.Icmp6Layer;
import it.unipr.netsec.ipstack.icmp6.Icmp6Message;
import it.unipr.netsec.ipstack.icmp6.NeighborDiscoveryClient;
import it.unipr.netsec.ipstack.icmp6.NeighborDiscoveryServer;
import it.unipr.netsec.ipstack.icmp6.SolicitedNodeMulticastAddress;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6RouterAdvertisementMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6RouterSolicitationMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6DestinationUnreachableMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6NeighborAdvertisementMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6NeighborSolicitationMessage;
import it.unipr.netsec.ipstack.icmp6.message.option.Icmp6Option;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Layer;
import it.unipr.netsec.ipstack.net.LayerListener;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;

import java.nio.ByteBuffer;


/** IPv6 interface for sending and receiving IPv6 packets through an Ethernet-like layer.
 * <p>
 * Layer-two address resolution is performed through the ICMPv6 Neighbor Discovery protocol.
 */
public class Ip6EthInterface extends NetInterface {
	
	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	/** ARP table timeout */
	public static long ARP_TABLE_TIMEOUT=60000;
	
	/** IP address */
	public Ip6AddressPrefix ip_addr;

	/** Prefix length */
	int prefix_len;

	Ip6Address linkl_addr;
	public boolean waitingForRouter = false;
	
	public int waitingForNeighbor = 0;
	/** Addresses of attached networks */
	//Ip6Prefix[] net_addresses;
	
	private Ip6Address sn_m_addr;

	/** Ethernet layer */
	public EthLayer eth_layer;

	/** Neighbor DiscoveryServer client */
	public NeighborDiscoveryClient nd_client=null;

	/** Neighbor DiscoveryServer server */
	public NeighborDiscoveryServer nd_server=null;

	Icmp6Message neighbor_adv_response = null;
	
	/** This Ethernet listener */
	LayerListener this_eth_listener;

	
	
	/** Creates a new IP interface.
	 * @param eth_ni an Ethernet-like interface
	 * @param ip_addr the IP address and prefix length */
	public Ip6EthInterface(NetInterface eth_ni, Ip6AddressPrefix ip_addr) {
		this(new EthLayer(eth_ni),ip_addr);
	}

		
	/** Creates a new IP interface.
	 * @param eth_layer the Ethernet layer
	 * @param ip_addr the IP address and prefix length */
	public Ip6EthInterface(EthLayer eth_layer, Ip6AddressPrefix ip_addr) {
		super(ip_addr);
		this.eth_layer=eth_layer;
		this.ip_addr = ip_addr;
		this.linkl_addr = ip_addr;
		this.prefix_len=ip_addr.prefix_len;
		this.sn_m_addr=new SolicitedNodeMulticastAddress(ip_addr);
		eth_layer.getEthInterface().addAddress(new EthMulticastAddress(this.sn_m_addr));
		this_eth_listener=new LayerListener() {
			@Override
			public void onIncomingPacket(Layer layer, Packet pkt) {
				processIncomingPacket(pkt);
			}
		};
		eth_layer.addListener(new Integer(EthPacket.ETH_IP6),this_eth_listener);
		// start Neighbor Discovery service
		EthAddress eth_addr=(EthAddress)eth_layer.getAddress();
		nd_server=new NeighborDiscoveryServer(this,ip_addr,eth_addr);
		nd_client=new NeighborDiscoveryClient(this,ip_addr,eth_addr,ARP_TABLE_TIMEOUT);
	}

	/** Creates a new IP interface.
	 * @param eth_layer the Ethernet layer */
	public Ip6EthInterface(EthLayer eth_layer) throws Exception {
		this (eth_layer, getIPAddr(eth_layer)); // Calling getIPAddr to do EUI64 calculations, then, calling standard constructor
		Icmp6Option emptyOptions []= null;
		Icmp6NeighborSolicitationMessage nsm = new Icmp6NeighborSolicitationMessage(this.linkl_addr, this.sn_m_addr, this.linkl_addr, emptyOptions);
		this.send(nsm.toIp6Packet(), this.sn_m_addr);
		// While testing, we tried out a "MAX TRIALS" of 5. The program sleeps 1sec between each one.
		while (this.waitingForNeighbor<5 && this.neighbor_adv_response==null) {
			Thread.sleep(1000);
			this.waitingForNeighbor++;
		}
		// If the response ain't null, there's a Node on the link with the same address.
		if(this.neighbor_adv_response!=null) {
			System.out.println("Existing address! Please configure me manually.");
			throw new Exception ("Existing address!");	
		}else {
			// If not, we try to get a prefix from the Router
			Icmp6RouterSolicitationMessage rsm = new Icmp6RouterSolicitationMessage(this.linkl_addr, new Ip6Address("ff02::2"), emptyOptions);
			this.waitingForRouter=true;
			this.send(rsm.toIp6Packet(), rsm.getDestAddress());
			while(this.waitingForRouter) {
				Thread.sleep(5000);
			}
		}
	}
	
	
	/** Calculates the possible link-local address using EUI64
	 * @param eth_layer the Ethernet layer*/
	private static Ip6AddressPrefix getIPAddr(EthLayer eth_layer) {
		EthAddress eth_addr=(EthAddress)eth_layer.getAddress();
		byte[] mac_bytes = eth_addr.getBytes();
		byte[] addr_bytes = new byte[8];
		String ip6AddrString = "fe80:";
		addr_bytes[0] = mac_bytes[0];
		addr_bytes[1] = mac_bytes[1];
		addr_bytes[2] = mac_bytes[2];
		addr_bytes[3] = new Byte((byte)255);
		addr_bytes[4] = new Byte((byte)254);
		addr_bytes[5] = mac_bytes[3];
		addr_bytes[6] = mac_bytes[4];
		addr_bytes[7] = mac_bytes[5];
		int intByte = (int)addr_bytes[0];
		byte convertedByte=(byte) intByte;
		
		String s = Integer.toBinaryString(convertedByte & 0xff);
		
		int length = s.length();
		char bits[]=s.toCharArray();
		bits[bits.length-2] = (bits[bits.length-2] == '1') ?  '0' : '1';
		s = new String(bits);
		addr_bytes[0] = (byte)(Integer.parseInt(s,2));
		for (int i=0;i<8;i++) {
			ip6AddrString = (i%2)==0 ? ip6AddrString.concat(":") : ip6AddrString;
			ip6AddrString = ip6AddrString.concat(String.format("%02x", addr_bytes[i]));
		}
		return new Ip6AddressPrefix(ip6AddrString, 64);
	}
	
	/** Gets the Ethernet address.
	 * @return the address */
	public EthAddress getEthAddress() {
		return (EthAddress)eth_layer.getAddress();
	}

	/*/** Gets addresses of attached networks.
	 * @return the network addresses */
	/*public Ip6Prefix[] getNetAddresses() {
		return net_addresses;
	}*/
	public boolean isConfigured () {
		return !this.waitingForRouter;
	}
	
	@Override
	public void send(final Packet pkt, final Address dest_addr) {
		final Ip6Packet ip_pkt=(Ip6Packet)pkt;
		if (ip_pkt.getSourceAddress()==null) ip_pkt.setSourceAddress(getAddress());		
		(new Thread() {
			public void run() {
				if (DEBUG) debug("send(): IP packet: "+ip_pkt);
				Ip6Address dest_ip_addr=(Ip6Address)dest_addr;
				EthAddress dst_eth_addr=null;
				if (dest_ip_addr.isMulticast()) dst_eth_addr=new EthMulticastAddress(dest_ip_addr);
				else dst_eth_addr=nd_client.lookup(dest_ip_addr);
				if (dst_eth_addr==null) dst_eth_addr=EthAddress.BROADCAST_ADDRESS;
				EthPacket eth_pkt=new EthPacket(eth_layer.getAddress(),dst_eth_addr,EthPacket.ETH_IP6,ip_pkt.getBytes());
				eth_layer.send(eth_pkt);
				if (DEBUG) debug("send(): IP packet ("+ip_pkt.getPayloadType()+") sent to "+dst_eth_addr);
				// promiscuous mode
				for (NetInterfaceListener li : promiscuous_listeners) {
					try { li.onIncomingPacket(Ip6EthInterface.this,ip_pkt); } catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}).start();
	}

	/** This method updates the interface's address by adding the net prefix.
	 * @param ip_msg the Router Advertisement message*/
	private void finishSLAA(Icmp6Message ip_msg) {
		Icmp6RouterAdvertisementMessage router_adv = new Icmp6RouterAdvertisementMessage(ip_msg);
		byte[] advertisement_bytes = new byte[32];
		router_adv.getOptions()[0].getBytes(advertisement_bytes, 0, 30);
		int prefix_len = advertisement_bytes[2];
		byte[] prefix_bytes = new byte[16];
		System.arraycopy(advertisement_bytes, 16, prefix_bytes, 0, 16);
		
		Ip6Address router_prefix_addr = new Ip6Address(prefix_bytes);
		char currentIP [] = this.ip_addr.toString().toCharArray();
		char routerPref[] = router_prefix_addr.toString().toCharArray();
		for(int i=0;i<prefix_len/4;i++) {
			currentIP[i] = routerPref[i];
		}
		this.ip_addr = new Ip6AddressPrefix(new String(currentIP), this.prefix_len);
		this.addresses.add(0, this.ip_addr);
		eth_layer.getEthInterface().addAddress(new
				EthMulticastAddress(new SolicitedNodeMulticastAddress(ip_addr)));
		new NeighborDiscoveryServer(this,ip_addr,(EthAddress)eth_layer.getAddress());
		this.waitingForRouter=false;
	}
	
	/** Processes an incoming Ethernet packet. */
	private void processIncomingPacket(Packet pkt) {
		EthPacket eth_pkt=(EthPacket)pkt;
		if (eth_pkt.getType()!=EthPacket.ETH_IP6) {
			throw new RuntimeException("It is not an IPv6 packet (type=0x"+Integer.toHexString(eth_pkt.getType())+")");
		}

		Ip6Packet ip_pkt=Ip6Packet.parseIp6Packet(eth_pkt.getPayloadBuffer(),eth_pkt.getPayloadOffset(),eth_pkt.getPayloadLength());
		if (DEBUG) debug("processIncomingPacket(): IP packet: "+ip_pkt);
		// For each type of ICMP6 message, we have a different behavior
		if (ip_pkt.getPayloadType()==Ip6Packet.IPPROTO_ICMP6) {
			Icmp6Message icmp_msg=new Icmp6Message(ip_pkt);
			int icmp_type=icmp_msg.getType();
			if (icmp_type==Icmp6Message.TYPE_Neighbor_Solicitation) { // If it's a neighbor solicitation, the answer will be a Neighbor Advertisement
				EthAddress eth_addr=(EthAddress)eth_pkt.getSourceAddress();
				Ip6Address ip_addr=(Ip6Address)ip_pkt.getSourceAddress();
				nd_client.put(ip_addr,eth_addr);
				Icmp6Option[] options = null;
				Icmp6NeighborAdvertisementMessage nam = new Icmp6NeighborAdvertisementMessage(this.ip_addr, (Ip6Address)ip_pkt.getSourceAddress(), true, true, true, (Ip6Address)ip_pkt.getSourceAddress(), options);
				//this.send(nam.toIp6Packet(), (Ip6Address)ip_pkt.getSourceAddress());
			}
			else if (icmp_type==Icmp6Message.TYPE_Neighbor_Advertisement && this.ip_addr==this.linkl_addr) { // If we received a neighbor advertisement, we save it. The constructor will do the rest.
				this.neighbor_adv_response = icmp_msg;
			}
			else if (icmp_type==Icmp6Message.TYPE_Router_Advertisement && this.waitingForRouter) { // If we received a Router Advertisement, we call finishSLAA to add the right network address.
				// If the Managed flag is true, the host should not autoconfigurate
				if (!(new Icmp6RouterAdvertisementMessage(icmp_msg).getMFlag()))
					this.finishSLAA(new Icmp6Message(ip_pkt));
			}
			else if (icmp_type==Icmp6Message.TYPE_Router_Solicitation) { // If a router solicitation got here, we're in a router. So, we send a Router Advertisement to who requested it.
				Icmp6Option[] options = new Icmp6Option[1];
				byte flags = (byte)0xc0;
				flags = (byte) (flags | (1 << 1));
				options [0] = new PrefixInformationOption(prefix_len, flags, ByteBuffer.allocate(6).putInt(99999).array(), ByteBuffer.allocate(6).putInt(99999).array(), ip_addr);
				Icmp6RouterAdvertisementMessage ram = new Icmp6RouterAdvertisementMessage(this.ip_addr, (Ip6Address)ip_pkt.getSourceAddress(), 10, false, true, 10000, 10000, 10000, options);
				this.send(ram.toIp6Packet(), ip_pkt.getSourceAddress());
			}
		}
		// promiscuous mode
		for (NetInterfaceListener li : promiscuous_listeners) {
			try { li.onIncomingPacket(this,ip_pkt); } catch (Exception e) {
				e.printStackTrace();
			}
		}
		// non-promiscuous mode
		for (NetInterfaceListener li : listeners) {
			try { li.onIncomingPacket(this,ip_pkt); } catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	
	@Override
	public void close() {
		nd_client.close();
		nd_server.close();
		eth_layer.removeListener(this_eth_listener);
		super.close();
	}	

}
