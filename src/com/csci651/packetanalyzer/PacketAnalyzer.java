package com.csci651.packetanalyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class PacketAnalyzer {

    private static int byteArrayToInt(byte[] bytes) {
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) + (b & 0xFF);
        }
        return value;
    }

    private static String toBitString(final byte[] bytes) {
        final char[] bits = new char[8 * bytes.length];
        for(int i = 0; i < bytes.length; i++) {
            final byte byteval = bytes[i];
            int bytei = i << 3;
            int mask = 0x1;
            for(int j = 7; j >= 0; j--) {
                final int bitval = byteval & mask;
                if(bitval == 0) {
                    bits[bytei + j] = '0';
                } else {
                    bits[bytei + j] = '1';
                }
                mask <<= 1;
            }
        }
        return String.valueOf(bits);
    }

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

    public static void main(String[] args) {
        String filename = args[0];
        byte[] dest = new byte[6];
        byte[] src = new byte[6];
        byte[] type = new byte[2];
        try {
            InputStream fis = new FileInputStream(filename);
            System.out.println("ETHER:  ----- Ether Header -----");
            System.out.println("ETHER:");
            fis.read(dest);
            char[] hex1 = byteArrayToHexadecimal(dest);
            String addr1 = new String(hex1).replaceAll(".{2}(?=.)", "$0:");
            System.out.println("ETHER:  Destination = " + addr1);

            fis.read(src);
            char[] hex2 = byteArrayToHexadecimal(src);
            String addr2 = new String(hex2).replaceAll(".{2}(?=.)", "$0:");
            System.out.println("ETHER:  Source = " + addr2);

            fis.read(type);
            int v4 = byteArrayToInt(type);
            char[] h3 = byteArrayToHexadecimal(type);
            System.out.println("ETHER:  Ethertype = " + new String(h3) + " (IP)");
            System.out.println("ETHER:");

            fis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
