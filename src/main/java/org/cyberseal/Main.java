package org.cyberseal;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;


public class Main {

    private static InetAddress sendProbePacket(InetAddress address) throws IOException {

        System.out.println("scanning for active network device in "+ address.getHostAddress()  +" ip address");

        String ipAddress = address.getHostAddress();
        String community = "public";
        int snmpVersion = SnmpConstants.version2c;

        String sysNameOid = "1.3.6.1.2.1.1.5.0";

        try {

            Snmp snmp = new Snmp(new DefaultUdpTransportMapping());
            snmp.listen();

            Address targetAddress = GenericAddress.parse("udp:" + ipAddress + "/161");
            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString(community));
            target.setAddress(targetAddress);
            target.setVersion(snmpVersion);

            PDU pdu = new PDU();
            pdu.add(new VariableBinding(new OID(sysNameOid)));
            pdu.setType(PDU.GET);

            ResponseEvent response = snmp.send(pdu, target);
            PDU responsePDU = response.getResponse();

            if (responsePDU != null) {
                String deviceName = responsePDU.get(0).getVariable().toString();
                System.out.println("Device Name: " + deviceName);
                return address;
            } else {
                System.out.println("Error: Response PDU is null.");
                return null;
            }



//            Loop to keep the program running
//            while (true) {
//                Thread.sleep(1000);
//            }

        } catch (Exception e) {
            System.err.println("Error: " + e);
            return null;
        }


    }

    public static void main(String[] args) throws UnknownHostException {

        String subnetMask = "255.255.255.0";  // Example Subnet Mask

        String ipAddress = "192.168.0.1"; // Example IP address

        // we need to retrieve this IP address and subnetMask via a program

        IpAddressRange IpRange = new IpAddressRange(ipAddress, subnetMask);

        LinkedList<InetAddress> discoveredDevices = new LinkedList<>();

        String firstUsableIpAddress = IpRange.getFirstUsableBytes();
        String lastUsableIpAddress = IpRange.getLastUsableBytes();

        System.out.println("First Usable Address: " + firstUsableIpAddress);
        System.out.println("last Usable Address: " + lastUsableIpAddress);


        // now we need to scan this range of addresses to discover all the devices

        String startIP = firstUsableIpAddress;
        String endIP = lastUsableIpAddress;



        try {
            InetAddress startAddress = InetAddress.getByName(startIP);
            InetAddress endAddress = InetAddress.getByName(endIP);

            InetAddress currentAddress = startAddress;

            while (!currentAddress.equals(endAddress)) {

                InetAddress ActiveDeviceAddress = sendProbePacket(currentAddress);

                if(ActiveDeviceAddress != null){
                    discoveredDevices.add(ActiveDeviceAddress);
                }

                byte[] ipBytes = currentAddress.getAddress();

                for (int i = ipBytes.length - 1; i >= 0; i--) {

                    if ((ipBytes[i] & 0xFF) < 255) {
                        ipBytes[i]++;
                        break;
                    }
                    else {
                        ipBytes[i] = 0;
                    }
                }
                currentAddress = InetAddress.getByAddress(ipBytes);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

    }



}