package it.unipr.netsec.nemo.examples;


import it.unipr.netsec.ipstack.analyzer.LibpcapHeader;
import it.unipr.netsec.ipstack.analyzer.LibpcapSniffer;
import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.ethernet.EthLayer;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6AddressPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6EthInterface;
import it.unipr.netsec.ipstack.ip6.Ip6Layer;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.nemo.ip.Ip6Host;
import it.unipr.netsec.nemo.ip.Ip6Router;
import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.link.DataLink;
import it.unipr.netsec.nemo.link.EthLinkInterface;
import it.unipr.netsec.nemo.link.PromiscuousLinkInterface;
import it.unipr.netsec.nemo.routing.ShortestPathAlgorithm;
import it.unipr.netsec.nemo.routing.sdn.SdnRouting;


/** IPv6 SLAA tests.
 * <p>
 * Two hosts host1 and host2 are connected via a DataLink and try to auto configurate themselves.
 */
public class IPv6SLAATests {

	public static void main(String[] args) throws Exception {
		long bit_rate=1000000; // 1Mb/s
		DataLink dl = new DataLink(bit_rate);
		new LibpcapSniffer(new PromiscuousLinkInterface(dl),LibpcapHeader.LINKTYPE_ETHERNET,"IPv6SLAA-trace.pcap");
		
		EthLinkInterface router_int = new EthLinkInterface(dl);

		EthLayer router_layer = new EthLayer(router_int);

		Ip6EthInterface router_inter = new Ip6EthInterface(router_layer,  new Ip6AddressPrefix("2001::cdba:3257:9652", 64));

		Ip6EthInterface interfaces [] = {router_inter};

		
		Ip6Router router = new Ip6Router(null, interfaces);

		
		System.out.println(router.getRoutingTable().toString());
		
		EthLinkInterface host1_net_interface = new EthLinkInterface(dl, new EthAddress("8c:85:90:a5:09:60"));
		EthLayer host1_eth_layer = new EthLayer(host1_net_interface);
		Ip6EthInterface host1_ip6interface= new Ip6EthInterface(host1_eth_layer);
		Ip6Host host1 = new Ip6Host(host1_ip6interface);
//		System.out.println(host1.getAddress().toString());


		EthLinkInterface host2_net_interface = new EthLinkInterface(dl, new EthAddress("8c:85:90:a5:98:60"));
		EthLayer host2_eth_layer = new EthLayer(host2_net_interface);
		Ip6EthInterface host2_ip6interface = new Ip6EthInterface(host2_eth_layer);

		Ip6Host host2 = new Ip6Host(host2_ip6interface);
//		System.out.println(host2.getAddress().toString());
		System.out.println("Host1:\n" + host1.getRoutingTable().toString());

		System.out.println("Host2:\n" + host2.getRoutingTable().toString());
		
		while (!((Ip6EthInterface)host2.getNetInterfaces()[0]).isConfigured());
		for (Address a: host2.getNetInterfaces()[0].getAddresses()) {
	         System.out.println(a);
	}
		System.out.println("Host1: "+host1.getAddress().toString()+" HOST2: "+ host2.getAddress().toString());

		host2.ping((Ip6Address)host1.getAddress(),5,System.out);
	}

}