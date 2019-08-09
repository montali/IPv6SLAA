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

package it.unipr.netsec.nemo.ip;


import java.io.PrintStream;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6RouterSolicitationMessage;
import it.unipr.netsec.ipstack.icmp6.message.option.Icmp6Option;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.icmp6.Icmp6Layer;
import it.unipr.netsec.ipstack.icmp6.Ping6Client;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6AddressPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6EthInterface;
import it.unipr.netsec.ipstack.ip6.Ip6Layer;
import it.unipr.netsec.ipstack.ip6.Ip6Node;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;
import it.unipr.netsec.ipstack.net.NetAddress;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.routing.Route;


/** IPv6 Host.
 * It is an IP node with a PING client.
 */
public class Ip6Host extends Ip6Node {

	/** Debug mode */
	public static boolean DEBUG=true;

	/** Prints a debug message. */
	void debug(String str) {
		//SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
		SystemUtils.log(LoggerLevel.DEBUG,Ip6Host.class.getSimpleName()+"["+getID()+"]: "+str);
	}

	
	/** IP layer built on top of this node and used by the PING client */
	Ip6Layer ip_layer;

	
	/** Creates a new host.
	 * @param ni network interface
	 * @param gw default router */
	public Ip6Host(NetInterface ni, IpAddress gw, Icmp6Layer icmp_layer) {
		super(new NetInterface[] {ni});
		System.out.println("RT: \n"+getRoutingTable());
		Icmp6Option options [] = null;
		Icmp6RouterSolicitationMessage rsm = new Icmp6RouterSolicitationMessage((Ip6Address)ni.getAddress(), new Ip6Address("FF02::2"), options);
		icmp_layer.send(rsm);
		if (gw!=null) getRoutingTable().setDefaultRoute(gw);
		ip_layer=new Ip6Layer(this);
	}

	
	/** Creates a new host.
	 * @param ni network interface
	 * @param gw default router */
	public Ip6Host(NetInterface ni, IpAddress gw) {
		super(new NetInterface[] {ni});
		System.out.println("RT: \n"+getRoutingTable());
		if (gw!=null) getRoutingTable().setDefaultRoute(gw);
		ip_layer=new Ip6Layer(this);
		Icmp6Option options [] = null;
		Icmp6RouterSolicitationMessage rsm = new Icmp6RouterSolicitationMessage((Ip6Address)ni.getAddress(), new Ip6Address("FF02::2"), options);
		ip_layer.getIcmp6Layer().send(rsm);
	}
	
	public Ip6Host (NetInterface ni) {
		super(new NetInterface[] {ni});
		ip_layer=new Ip6Layer(this);
		Icmp6Option options [] = null;
		Icmp6RouterSolicitationMessage rsm = new Icmp6RouterSolicitationMessage((Ip6Address)ni.getAddress(), new Ip6Address("FF02::2"), options);
		ip_layer.getIcmp6Layer().send(rsm);
	}
	
	/** Creates a new host.
	 * @param link attached IP link
	 * @param addr the IP address
	 * @param gw default router */
	public Ip6Host(IpLink link, Ip6Address addr, Ip6Address gw) {
		this(new IpLinkInterface(link,addr ),gw, null);
	}
		
	/** Creates a new host.
	 * The IP address and default router are automatically configured
	 * @param link attached IP link */
	public Ip6Host(IpLink link) {
		this(new IpLinkInterface(link),(link.getRouters().length>0?(IpAddress)link.getRouters()[0]:null), null);
	}

	
//	public Ip6Host (IpAddress gw) {
//		this.ne
//		Ip6Address ll_addr = new Ip6Address()
//		super
//	}
	
	/** Gets the host address.
	 * @return the first address of the network interface */
	public Ip6Address getAddress() {
		return (Ip6Address)getNetInterfaces()[0].getAddress();
	}

	/** Runs a ping session.
	 * It sends a given number of ICMPv6 Echo Request messages and captures the corresponding ICMPv6 Echo Reply responses.
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param out output where ping results are printed */
	public void ping(final Ip6Address target_ip_addr, int count, final PrintStream out) {
		new Ping6Client(ip_layer,target_ip_addr,count,out);
	}

	/*@Override
	public String toString() {
		return getClass().getSimpleName()+'['+getNetInterfaces()[0].getAddress()+']';
	}*/

}
