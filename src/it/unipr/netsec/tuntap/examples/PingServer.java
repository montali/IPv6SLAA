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

package it.unipr.netsec.tuntap.examples;


import it.unipr.netsec.ipstack.icmp4.IcmpMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoReplyMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoRequestMessage;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.tuntap.TunPacket;
import it.unipr.netsec.tuntap.TunSocket;

import java.io.IOException;

import org.zoolu.util.Flags;


/** ICMP server that responds to any ICMP Echo request.
 * It replies with the corresponding ICMP Echo reply.
 */
public class PingServer {

	public static void main(String[] args) throws IOException {
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		String tun_interface=flags.getString(null,"<tun-interface>",null,"TUN interface (e.g. tun0)");
		if (help || tun_interface==null) {
			System.out.println(flags.toUsageString(PingServer.class.getSimpleName()));
			System.exit(0);			
		}
		TunSocket tun=new TunSocket(tun_interface);
		System.out.println("TUN interface is open");
		while (true) {
			TunPacket tun_pkt=tun.receive();
			System.out.println("Packet received: "+tun_pkt.toString());
			if (tun_pkt.getPayloadType()==TunPacket.TYPE_IP) {
				Ip4Packet ip_pkt=Ip4Packet.parseIp4Packet(tun_pkt.getPayload());
				System.out.println("\tIP packet: "+ip_pkt.toString());
				if (ip_pkt.getProto()==Ip4Packet.IPPROTO_ICMP) {
					IcmpMessage icmp_msg=new IcmpMessage(ip_pkt.getSourceAddress(),ip_pkt.getDestAddress(),ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
					System.out.println("\tICMP message: "+icmp_msg);
					if (icmp_msg.getType()==IcmpMessage.TYPE_Echo_Request) {
						IcmpEchoRequestMessage icmp_echo_request=new IcmpEchoRequestMessage(icmp_msg);
						System.out.println("\tICMP Echo request from "+icmp_echo_request.getSourceAddress());
						// send the Echo reply
						IcmpEchoReplyMessage icmp_echo_reply=new IcmpEchoReplyMessage(icmp_echo_request.getDestAddress(),icmp_echo_request.getSourceAddress(),icmp_echo_request.getIdentifier(),icmp_echo_request.getSequenceNumber(),icmp_echo_request.getEchoData());
						System.out.println("\tSending ICMP Echo reply: "+icmp_echo_reply);						
						tun_pkt=new TunPacket(icmp_echo_reply.toIp4Packet());
						tun.send(tun_pkt);
					}
				}
			}
		}
	}

}
