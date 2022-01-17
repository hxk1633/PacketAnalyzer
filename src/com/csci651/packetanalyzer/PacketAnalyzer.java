package com.csci651.packetanalyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class PacketAnalyzer {

    private static int byteArrayToInt(byte[] bytes) {
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) + (b & 0xFF);
        }
        return value;
    }

    private static char[] byteArrayToHexadecimal(byte[] bytes) {
        int len = bytes.length;

        char[] hexValues = "0123456789ABCDEF".toCharArray();
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
        File f = new File(filename);
        byte[] preamble = new byte[8];
        byte[] dest = new byte[6];
        byte[] src = new byte[6];
        byte[] type = new byte[2];
        try {
            FileInputStream fis = new FileInputStream(f);
            fis.read(preamble);
            System.out.println("ETHER:  ----- Ether Header -----");
            System.out.println("ETHER:                          ");
            System.out.println("Preamble");
            int v1 = byteArrayToInt(preamble);
            System.out.println(v1);

            fis.read(dest);
            int v2 = byteArrayToInt(dest);
            char[] h1 = byteArrayToHexadecimal(dest);
            System.out.println("ETHER:  Destination = " + v2);
            System.out.println("ETHER:  Destination = " + h1);

            fis.read(src);
            int v3 = byteArrayToInt(src);
            char[] h2 = byteArrayToHexadecimal(src);
            System.out.println("ETHER:  Source = " + v3);
            System.out.println("ETHER:  Source = " + h2);

            fis.read(type);
            int v4 = byteArrayToInt(type);
            char[] h3 = byteArrayToHexadecimal(type);
            System.out.println("ETHER:  Ethertype = " + v4);
            System.out.println("ETHER:  Ethertype = " + h3);

            fis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
