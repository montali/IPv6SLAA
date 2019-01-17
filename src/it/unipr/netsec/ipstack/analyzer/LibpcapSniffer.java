package it.unipr.netsec.ipstack.analyzer;


import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;


import org.zoolu.util.Clock;

import it.unipr.netsec.ipstack.ip4.Ip4Interface;
import it.unipr.netsec.ipstack.ip6.Ip6Interface;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.rawsocket.ethernet.RawEthInterface;


/** Libpcap-compatible sniffer.
 * Attached to a network interface, it captures all packets and writes them to a file using standard libpcap format.
 */
public class LibpcapSniffer {

	/** Libpcap output file */
	FileOutputStream out;

	/** start time in milliseconds */
	long start_millisecs;

	/** start time in nanoseconds */
	long start_nanosecs;

	/** Whether to skip SSH packets (TCP port 22) */
	boolean no_ssh=false;

	
	/** Create a new sniffer.
	 * @param ni the network interface
	 * @param file_name the pcap file where packets will be written
	 * @throws IOException */
	public LibpcapSniffer(NetInterface ni, String file_name) throws IOException {
		int link_type=
			ni instanceof RawEthInterface? LibpcapHeader.LINKTYPE_ETHERNET :
			ni instanceof Ip4Interface? LibpcapHeader.LINKTYPE_IPV4 :
			ni instanceof Ip6Interface? LibpcapHeader.LINKTYPE_IPV6 : -1;
		if (link_type>=0) init(ni,link_type,file_name);
		else throw new RuntimeException("interface type '"+ni.getClass().getSimpleName()+"' not supported for sniffing."); 
	}

	
	/** Create a new sniffer.
	 * @param ni the network interface
	 * @param type the interface type
	 * @param file_name the pcap file where packets will be written
	 * @throws IOException */
	public LibpcapSniffer(NetInterface ni, int type, String file_name) throws IOException {
		init(ni,type,file_name);
	}

	
	/** Inits the sniffer.
	 * @param ni the network interface
	 * @param type the interface type
	 * @param file_name the pcap file where packets will be written
	 * @throws IOException */
	private void init(NetInterface ni, int type, String file_name) throws IOException {
		out=new FileOutputStream(file_name);
		LibpcapHeader ph=new LibpcapHeader(type);
		ph.write(out);
		NetInterfaceListener listener=new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				try {
					//long timestamp=Clock.getDefaultClock().currentTimeMillis();
					//String packet_info=ProtocolAnalyzer.exploreInner(pkt).toString();
					//if (out!=null && (!no_ssh || packet_info.indexOf(":22 ")<0)) new LibpcapRecord(timestamp,pkt).write(out);
					long t_usecs=((Clock.getDefaultClock().nanoTime()-start_nanosecs)+start_millisecs*1000000)/1000;
					String packet_info=ProtocolAnalyzer.exploreInner(pkt).toString();
					if (out!=null && (!no_ssh || packet_info.indexOf(":22 ")<0)) new LibpcapRecord(t_usecs/1000000,t_usecs%1000000,pkt).write(out);
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		};
		if (ni instanceof RawEthInterface) ((RawEthInterface)ni).addPromiscuousListener(listener);
		else ni.addListener(listener);
	}

	
	/** Whether to skip SSH packets (TCP port 22).
	 * @param no_ssh <i>true</i> to skip SSH packets (TCP port 22) */
	public void skipSSH(boolean no_ssh) {
		this.no_ssh=no_ssh;
	}
	
	
	/** Stops capturing and closes the file. */
	public synchronized void close() {
		if (out!=null) {
			OutputStream temp=out;
			out=null;
			try { temp.close(); } catch (IOException e) {}
		}
	}
	
}
