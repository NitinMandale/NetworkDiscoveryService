package org.cyberseal;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class IpAddressRange {
    String IpAddress;
    byte[] IpAddressBytes;
    String subnetMask;
    byte[] subnetBytes;
    byte[] networkBytes=  new byte[4];

    public IpAddressRange(String address, String mask) throws UnknownHostException {

        IpAddress = address;
        subnetMask = mask;

        //calculating the network bytes

        InetAddress subnet = InetAddress.getByName(IpAddress);
        IpAddressBytes = subnet.getAddress();
        subnetBytes = InetAddress.getByName(subnetMask).getAddress();

        for (int i = 0; i < 4; i++) {
            networkBytes[i] = (byte) (subnetBytes[i] & IpAddressBytes[i]);
        }

    }



    public String getFirstUsableBytes() throws UnknownHostException {
        byte[] firstUsableBytes = networkBytes.clone();
        firstUsableBytes[3] += 1;
        InetAddress firstUsableAddress = InetAddress.getByAddress(firstUsableBytes);

        return firstUsableAddress.getHostAddress();
    }




    public String getLastUsableBytes() throws UnknownHostException {

        byte[] lastUsableBytes =  new byte[4];
        byte [] invertedSubnetMask = new byte[4];;

        for(int i=0; i< subnetBytes.length; i++ ) {

            invertedSubnetMask[i] = (byte) ~subnetBytes[i];
            lastUsableBytes[i] = (byte) (invertedSubnetMask[i] | IpAddressBytes[i]);
        }

        InetAddress lastUsableAddress = InetAddress.getByAddress(lastUsableBytes);

        return lastUsableAddress.getHostAddress();
    }

}
