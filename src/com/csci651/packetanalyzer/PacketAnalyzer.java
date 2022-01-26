package com.csci651.packetanalyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class PacketAnalyzer {

//    private static int byteArrayToInt(byte[] bytes) {
//        int value = 0;
//        for (byte b : bytes) {
//            value = (value << 8) + (b & 0xFF);
//        }
//        return value;
//    }

    private static char[] byteArrayToHexadecimal(byte[] bytes) {
        int len = bytes.length;

        char[] hexValues = "0123456789abcdef".toCharArray();
        char[] hexCharacter = new char[len * 2];

        for (int i = 0; i < len; i++) {
            int v = bytes[i] & 0xFF;
            hexCharacter[i * 2] = hexValues[v >>> 4];
            hexCharacter[i * 2 + 1] = hexValues[v & 0x0F];
        }
        return hexCharacter;
    }

    private static int unsignedIntFromByteArray(byte[] bytes) {
        int res = 0;
        if (bytes == null)
            return res;

        for (int i = 0; i < bytes.length; i++) {
            res = (res *10) + ((bytes[i] & 0xff));
        }
        return res;
    }

    private static int getBits(byte[] bytes, int numBits, int startBit) {
//        int value = 0;
//        for (byte b : bytes) {
//            value = (value << 8) + (b & 0xFF);
//        }
        int value = unsignedIntFromByteArray(bytes);
        return (((1 << numBits) - 1) & (value >> (startBit - 1)));
    }

    private static int getBitsFromByte(byte b, int numBits, int startBit) {
        return (((1 << numBits) - 1) & (b >>> (startBit - 1)));
    }

    private static String bytesToHex(byte[] bytes) {
        String hex = "";
        for (byte b : bytes) {
            hex += String.format("%02X", b);
        }
        return hex;
    }

    public static void main(String[] args) {
        String filename = args[0];
        File file = new File(filename);
        byte[] dest = new byte[6];
        byte[] src = new byte[6];
        byte[] type = new byte[2];
        byte[] ip = new byte[4];
        byte[] tcp = new byte[4];
//        byte[] ip1 = new byte[4];
//        byte[] ip2 = new byte[4];
//        byte[] ip3 = new byte[4];
//        byte[] ip4 = new byte[4];
//        byte[] ip5 = new byte[4];
        try {
            InputStream fis = new FileInputStream(file);
            System.out.println("ETHER:  ----- Ether Header -----");
            System.out.println("ETHER:");
            System.out.println("ETHER:  Packet size = " + file.length() + " bytes");

            fis.read(dest);
            char[] hex1 = byteArrayToHexadecimal(dest);
            String addr1 = new String(hex1).replaceAll(".{2}(?=.)", "$0:");
            System.out.println("ETHER:  Destination = " + addr1);

            fis.read(src);
            char[] hex2 = byteArrayToHexadecimal(src);
            String addr2 = new String(hex2).replaceAll(".{2}(?=.)", "$0:");
            System.out.println("ETHER:  Source = " + addr2);

            fis.read(type);
            char[] h3 = byteArrayToHexadecimal(type);
            System.out.println("ETHER:  Ethertype = " + new String(h3) + " (IP)");
            System.out.println("ETHER:");

            System.out.println("IP:   ----- IP Header -----");
            System.out.println("IP:");

            fis.read(ip);
//            System.out.println(bytesToHex(ip1));
            int version = (ip[0] & 0xF0) >> 4;
            int hl = (ip[0] & 0x0F) * 4;
            int tos = (ip[1] & 0xFF);
            int tl = ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
            System.out.println("IP:   Version = " + version);
            System.out.println("IP:   Header length = " + hl + " bytes");
            System.out.println("IP:   Type of service = " + String.format("0x%02x", tos));
            System.out.println("IP:   Total length = " +  tl + " bytes");

            fis.read(ip);
            int id = ((ip[0] & 0xFF) << 8) | (ip[1] & 0xFF);
            int flags = ((ip[2]) & 0xF0) >> 4;
            int fragOffset = (((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF));
            System.out.println("IP:   Identification = " +  id);
            System.out.println("IP:   Flags = " +  String.format("0x%02x", flags));
            System.out.println("IP:   Fragment offset = " +  fragOffset + " bytes");

            fis.read(ip);
            int ttl = (ip[0] & 0xFF);
            int protocol = (ip[1] & 0xFF);
            int checksum = ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
            System.out.println("IP:   Time to live = " +  ttl + " seconds/hops");
            System.out.println("IP:   Protocol = " +  protocol);
            System.out.println("IP:   Header checksum = " +  String.format("0x%04x", checksum));

            fis.read(ip);
            int src1 = ip[0] & 0xFF;
            int src2 = ip[1] & 0xFF;
            int src3 = ip[2] & 0xFF;
            int src4 = ip[3] & 0xFF;
            String src_addr = String.format("%s.%s.%s.%s", src1, src2, src3, src4);
            System.out.println("IP:   Source address = " +  src_addr);

            fis.read(ip);
            int dst1 = ip[0] & 0xFF;
            int dst2 = ip[1] & 0xFF;
            int dst3 = ip[2] & 0xFF;
            int dst4 = ip[3] & 0xFF;
            String dst_addr = String.format("%s.%s.%s.%s", dst1, dst2, dst3, dst4);
            System.out.println("IP:   Destination address = " +  dst_addr);
            if (hl == 20) {
                System.out.println("IP:   No options");
            }

            if (protocol == 6) {
                fis.read(tcp);
                System.out.println("TCP:  ----- TCP Header -----");
                System.out.println("TCP:");
            } else if (protocol == 17) {
                fis.read(tcp);
                System.out.println("UDP:  ----- UDP Header -----");
                System.out.println("UDP:");
            } else if (protocol == 1) {
                fis.read(tcp);
                System.out.println("ICMP:  ----- ICMP Header ----- ");
                System.out.println("ICMP:");
            }




            fis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
