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

package it.unipr.netsec.ipstack.routing;


import java.util.ArrayList;

import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetAddress;


/** Routing Table.
 */
public class RoutingTable implements RoutingFunction {

	/** Table */
	ArrayList<Route> rt=new ArrayList<Route>();

	/** Default route */
	Route default_route=null;

	
	
	/** Creates a new routing table. */
	public RoutingTable() {
	}
	
	
	/** Gets the size of the routing table.
	 * @return the current size */
	public int size() {
		return rt.size();
	}

	
	/** Adds a new route.
	 * @param dest_naddr the destination network address
	 * @param next_hop the next-hop router */
	public void add(NetAddress dest_naddr, Address next_hop) {
		rt.add(new Route(dest_naddr,next_hop,getRoute(next_hop).getOutputInterface()));
	}
	
	
	/** Adds a new route.
	 * @param route the new route */
	public void add(Route route) {
		rt.add(route);
	}
	
	
	/** Inserts a new route.
	 * @param i the position within the routing table
	 * @param route the new route */
	public void insert(int i, Route route) {
		rt.add(i,route);
	}
	
	
	/** Removes a route.
	 * @param dest_naddr the destination of the route to be removed */
	public void remove(NetAddress dest_naddr) {
		for (int i=0; i<rt.size(); i++) {
			Route route_i=rt.get(i);
			if (route_i.getDestNetAddress().equals(dest_naddr)) {
				rt.remove(i);
				return;
			}
		}
	}

	
	/** Removes all routes. */
	public void removeAll() {
		rt.clear();
	}
	
	
	/** Removes a route.
	 * @param i the index of the route within the routing table */
	public void remove(int i) {
		rt.remove(i);
	}

	
	/** Gets all routes in the routing table.
	 * @return list of routes */
	public Route[] getRoutes() {
		return rt.toArray(new Route[]{});
	}

	
	/** Sets the default route.
	 * @param default_router the default router */
	public void setDefaultRoute(Address default_router) {
		setDefaultRoute(new Route(null,default_router,getRoute(default_router).getOutputInterface()));
	}
	
	
	/** Sets the default route.
	 * @param default_route the default route or <i>null</i> */
	public void setDefaultRoute(Route default_route) {
		this.default_route=default_route;
	}
	
	
	/** Gets the default route.
	 * @return the default route (if any) */
	public Route getDefaultRoute() {
		return default_route;
	}
	
	
	@Override
	public Route getRoute(Address dest_addr) {
		for (Route route : rt) {
			if (route.getDestNetAddress().contains(dest_addr)) return route;
		}
		// else
		return default_route;
	}

	
	@Override
	public String toString() {
		StringBuffer sb=new StringBuffer();
		sb.append("destination\tnext-hop\tinterface\n");
		for (int i=0; i<rt.size(); i++) {
			Route route=rt.get(i);
			sb.append(route.getDestNetAddress());
			sb.append('\t').append(route.getNextHop());
			sb.append('\t').append(route.getOutputInterface()).append('\n');
		}
		if (default_route!=null) {
			sb.append("default");
			sb.append('\t').append(default_route.getNextHop());
			sb.append('\t').append(default_route.getOutputInterface()).append('\n');
		}
		return sb.toString();
	}

	/** Gets a JSON representation of this object.
	 * @return the JSON */
	/*public JSONArray toJson() {
		JSONArray json=new JSONArray();
		ArrayList<JSONObject> list=new ArrayList<JSONObject>();
		for (Route r: rt) list.add(r.toJson());
		json.addAll(list);
		return json;
	}*/

}
