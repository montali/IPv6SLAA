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

package it.unipr.netsec.tuntap;


import java.io.IOException;


/** Linux TUN (TUNneling) socket.
 */
public class TunSocket {

	/** Loads the tuntap library */
	static {
		try { System.loadLibrary("tuntap-64"); }
		catch (Error e1) {
			try { System.loadLibrary("tuntap-32"); }
			catch (Error e2) {
				System.loadLibrary("tuntap");
			}
		}
	}

	
	/** Recever buffer */
	private byte[] recv_buffer=new byte[32768];
	
	/** File descriptor of the TUN socket */
	int fd;
 
	
	/** Creates a new TUN socket.
	 * @param name name of the interface (e.g. "tun0") 
	 * @throws IOException */
	public TunSocket(String name) throws IOException {
		fd=open(name);
		if (fd<0) throw new IOException("Unable to open the TUN interface '"+name+"'");
	}
		
		
	/** Sends a raw packet.
	 * @param buf the buffer used for passing the packet
	 * @param off the offset within the buffer
	 * @param len the length of the packet
	 * @return the number of characters written, i.e. the packet length in case of success; -1 on error */
	/*public int send(byte[] buf, int off, int len) {
		return this.write(fd,buf,off,len);
	}*/

	/** Sends a packet.
	 * @param pkt the packet to send 
	 * @throws IOException */
	public void send(TunPacket pkt) throws IOException {
		byte[] data=pkt.getBytes();
		int len=write(fd,data,0,data.length);
		if (len<0 || len!=data.length) throw new IOException("Send failure ("+len+")");
	}

	/** Receives a raw packet.
	 * @param buf the buffer used for returning the received packet
	 * @param off the offset within the buffer
	 * @return the number of characters read, i.e. the packet length */
	/*public int receive(byte[] buf, int off) {
		return read(fd,buf,off);		
	}*/
	
	/** Receives a packet.
	 * @return the received 
	 * @throws IOException */
	public TunPacket receive() throws IOException {
		TunPacket pkt=null;
		synchronized (recv_buffer) {
			int len=read(fd,recv_buffer,0);
			if (len<0) throw new IOException("Receive failure ("+len+")");
			byte[] data=new byte[len];
			System.arraycopy(recv_buffer,0,data,0,len);
			pkt=new TunPacket(data,0,len);
		}
		return pkt;
	}

	
	// *************************** Native methods: ***************************

	/** Opens a TUN socket.
	* @param name name of the interface (e.g. "tun0")
	* @return the new TUN identifier in case of success, -1 on error */
	private native int open(String name);
	 
	/** Writes a raw packet.
	 * @param fd file descriptor of the TUN interface
	 * @param buf the buffer used for passing the packet
	 * @param off the offset within the buffer
	 * @param len the length of the packet
	 * @return the number of characters written, i.e. the packet length in case of success; -1 on error */
	private native int write(int fd, byte[] buf, int off, int len);

	/** Reads a raw packet.
	 * @param fd file descriptor of the TUN interface
	 * @param buf the buffer used for returning the received packet
	 * @param off the offset within the buffer
	 * @return the number of characters read, i.e. the packet length */
	private native int read(int fd, byte[] buf, int off);

}
