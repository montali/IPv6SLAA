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

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.icmp4.PingClient;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4Node;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.net.NetInterface;


/** IPv4 Host.
 */
public class Ip4Host extends Ip4Node {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	void debug(String str) {
		//SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
		SystemUtils.log(LoggerLevel.DEBUG,Ip4Host.class.getSimpleName()+"["+getID()+"]: "+str);
	}

	
	/** Creates a new host.
	 * @param ni network interface
	 * @param gw default router */
	public Ip4Host(NetInterface ni, IpAddress gw) {
		super(new NetInterface[] {ni});
		if (gw!=null) getRoutingTable().setDefaultRoute(gw);
	}

	/** Creates a new host.
	 * The IP address and default router are automatically configured
	 * @param link attached link */
	public Ip4Host(IpLink link) {
		this(new IpLinkInterface(link),(link.getRouters().length>0?(IpAddress)link.getRouters()[0]:null));
	}
		
	/** Gets the host address.
	 * @return the first address of the network interface */
	public Ip4Address getAddress() {
		return (Ip4Address)getNetInterfaces()[0].getAddresses()[0];
	}

	/** Runs a ping session.
	 * It sends a given number of ICMP Echo Request messages and captures the corresponding ICMP Echo Reply responses.
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param out output where ping results are printed */
	public void ping(final Ip4Address target_ip_addr, int count, final PrintStream out) {
		new PingClient(new Ip4Layer(this),target_ip_addr,count,out);
	}

	/*@Override
	public String toString() {
		return getClass().getSimpleName()+'['+getAddress()+']';
	}*/

}
