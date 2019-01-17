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

package it.unipr.netsec.tuntap.ip4;


import java.io.IOException;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.tuntap.TunPacket;
import it.unipr.netsec.tuntap.TunSocket;


/** IPv4 interface for sending and receiving IPv4 packets through a TUN interface.
 */
public class Ip4TunInterface extends NetInterface {
	
	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	/** TUN interface */
	TunSocket tun;	

	/** Whether it is running */
	boolean is_running=true;	

	
	/** Creates a new IP interface.
	 * @param tun the TUN interface
	 * @param ip_addr the IP address and prefix length */
	public Ip4TunInterface(TunSocket tun, Ip4AddressPrefix ip_addr) {
		super(ip_addr);
		this.tun=tun;
		addAddress(Ip4Address.ADDR_BROADCAST);
		addAddress(Ip4Address.ADDR_ALL_HOSTS_MULTICAST);
		addAddress(ip_addr.getPrefix().getNetworkBroadcastAddress());
		new Thread() {
			public void run() {
				receiver();
			}
		}.start();
	}

	
	@Override
	public void send(final Packet pkt, final Address dest_addr) {
		Ip4Packet ip_pkt=(Ip4Packet)pkt;
		//if (DEBUG) debug("send(): IP packet: "+ip_pkt.toString());
		TunPacket tun_pkt=new TunPacket(ip_pkt);
		if (DEBUG) debug("send(): TUN packet: "+tun_pkt.toString());
		try {
			tun.send(tun_pkt);
		}
		catch (IOException e) {
			if (DEBUG) debug(e.toString());
		}
	}

	
	/** Receives packets. */
	private void receiver() {
		while (is_running) {
			TunPacket tun_pkt;
			try {
				tun_pkt=tun.receive();
				if (DEBUG) debug("receiver(): TUN packet: "+tun_pkt.toString());
				if (tun_pkt.getPayloadType()==TunPacket.TYPE_IP) {
					Ip4Packet ip_pkt=Ip4Packet.parseIp4Packet(tun_pkt.getPayload());
					//if (DEBUG) debug("receiver(): IP packet: "+ip_pkt.toString());
					for (NetInterfaceListener li : getListeners()) {
						try { li.onIncomingPacket(this,ip_pkt); } catch (Exception e) {
							e.printStackTrace();
						}
					}			
				}						
			}
			catch (IOException e) {
				if (DEBUG) debug(e.toString());
			}
		}
	}

	
	@Override
	public void close() {
		is_running=false;
		super.close();
	}
	
}
