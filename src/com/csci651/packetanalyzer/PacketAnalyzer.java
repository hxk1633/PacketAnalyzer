package com.csci651.packetanalyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class PacketAnalyzer {
    public static void main(String[] args) {
        String filename = args[0];
        try {
            FileInputStream fis = new FileInputStream(new File(filename));
            int ch;
            while ((ch = fis.read()) != -1) {
                System.out.print((char) ch);
            }

            fis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
