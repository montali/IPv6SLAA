package it.unipr.netsec.nemo.examples;


import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;
import it.unipr.netsec.nemo.ip.Ip6Host;
import it.unipr.netsec.nemo.ip.Ip6Router;
import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.routing.ShortestPathAlgorithm;
import it.unipr.netsec.nemo.routing.sdn.SdnRouting;


public class LinearIPv6Network {

	public static void main(String[] args) {
		long bit_rate=1000000; // 1Mb/s
		int n=50; // number of routers
		int c=3; // number of ping messages
		//Clock.setDefaultClock(new VirtualClock());

		// create all links
		IpLink[] links=new IpLink[n+1];
		for (int i=0; i<n+1; i++) links[i]=new IpLink(bit_rate,new Ip6Prefix("fc00:"+(i+1)+"::/64"));
		
		// dynamic routing
		SdnRouting routing=new SdnRouting(ShortestPathAlgorithm.DIJKSTRA);

		// create all routers
		Ip6Router[] routers=new Ip6Router[n];	
		for (int i=0; i<n; i++) {
			routers[i]=new Ip6Router(new IpLink[]{links[i],links[i+1]});
			routers[i].setDynamicRouting(routing);
		}
		
		// update all routing tables
		routing.updateAllNodes();
		
		Ip6Host host1=new Ip6Host(links[0]);		
		Ip6Host host2=new Ip6Host(links[n]);
		host1.ping((Ip6Address)host2.getAddress(),c,System.out);
	}

}
