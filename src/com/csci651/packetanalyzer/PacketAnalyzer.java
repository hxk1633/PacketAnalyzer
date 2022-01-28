package com.csci651.packetanalyzer;

import java.io.*;
import java.util.Arrays;

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

        char[] hexValues = "0123456789abcdef".toCharArray();
        char[] hexCharacter = new char[len * 2];

        for (int i = 0; i < len; i++) {
            int v = bytes[i] & 0xFF;
            hexCharacter[i * 2] = hexValues[v >>> 4];
            hexCharacter[i * 2 + 1] = hexValues[v & 0x0F];
        }
        return hexCharacter;
    }

    private static Boolean isKthBitSet(int n, int k) {
        if ((n & (1 << (k - 1))) > 0)
            return true;
        else
            return false;
    }

    private static void printTOSBits(int n) {
        Boolean delay = isKthBitSet(n, 5);
        Boolean throughput = isKthBitSet(n, 4);
        Boolean reliability = isKthBitSet(n, 3);
        System.out.println("\t\txxx. .... = 0 (precedence)");

        if (delay) {
            System.out.println("\t\t...1 .... = low delay");
        } else {
            System.out.println("\t\t...0 .... = normal delay");
        }

        if (throughput) {
            System.out.println("\t\t.... 1... = high throughput");
        } else {
            System.out.println("\t\t.... 0... = normal throughput");
        }

        if (reliability) {
            System.out.println("\t\t.... .1.. = high reliability");
        } else {
            System.out.println("\t\t.... .0.. = normal reliability");
        }

    }

    private static void printTCPBits(int n) {
        Boolean up = isKthBitSet(n, 6);
        Boolean ack = isKthBitSet(n, 5);
        Boolean push = isKthBitSet(n, 4);
        Boolean reset = isKthBitSet(n, 3);
        Boolean syn = isKthBitSet(n, 2);
        Boolean fin = isKthBitSet(n, 1);

        if (up) {
            System.out.println("\t\t..1. .... = Urgent pointer");
        } else {
            System.out.println("\t\t..0. .... = No urgent pointer");
        }

        if (ack) {
            System.out.println("\t\t...1 .... = Acknowledgement ");
        } else {
            System.out.println("\t\t...0 .... = No acknowledgement ");
        }

        if (push) {
            System.out.println("\t\t.... 1... = Push");
        } else {
            System.out.println("\t\t.... 0... = No push");
        }

        if (reset) {
            System.out.println("\t\t.... .1.. = Reset");
        } else {
            System.out.println("\t\t.... .0.. = No reset");
        }

        if (syn) {
            System.out.println("\t\t.... ..1. = Syn");
        } else {
            System.out.println("\t\t.... ..0. = No Syn");
        }

        if (fin) {
            System.out.println("\t\t.... ...1 = Fin");
        } else {
            System.out.println("\t\t.... ...0 = No Fin");
        }
    }

    private static void printfragBits(int n) {
        Boolean df = isKthBitSet(n, 7);
        Boolean mf = isKthBitSet(n, 6);
        if (df) {
            System.out.println("\t\t.1.. .... = do not fragment");
        } else {
            System.out.println("\t\t.0.. .... = OK to fragment");
        }

        if (mf) {
            System.out.println("\t\t..1. .... = more fragments");
        } else {
            System.out.println("\t\t..0. .... = last fragment");
        }
    }

    private static void print16DataBytes(byte[] data, int protocol) throws UnsupportedEncodingException {
        char[] hex_chr = byteArrayToHexadecimal(data);
        String hex_str =  new String(hex_chr);
        if (protocol == 6) {
            System.out.print("TCP:  " + hex_str);
        } else if (protocol == 17) {
            System.out.print("UDP:  " + hex_str);
        }
        System.out.print("\t\t'" + new String(data, "UTF-8").replaceAll("[^\\p{ASCII}]", ".").replaceAll("[\\n\\t ]", ".") + "'\n");
    }

    public static void main(String[] args) {
        String filename = args[0];
        File file = new File(filename);
        byte[] dest = new byte[6];
        byte[] src = new byte[6];
        byte[] type = new byte[2];
        byte[] ip = new byte[4];
        byte[] tcp = new byte[4];
        byte[] udp = new byte[4];
        byte[] icmp = new byte[4];
        byte[] data = new byte[16];
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
            String ethertype_str = new String(h3);
            if (ethertype_str.equals("0800")) {
                ethertype_str = ethertype_str + " (IP)";
            } else {
                if (ethertype_str.equals("0806")) {
                    ethertype_str = ethertype_str + " (ARP)";
                }
                System.out.println("ETHER:  Ethertype = " + ethertype_str);
                System.out.println("ETHER:");
                System.exit(0);
            }
            System.out.println("ETHER:  Ethertype = " + ethertype_str);
            System.out.println("ETHER:");

            System.out.println("IP:   ----- IP Header -----");
            System.out.println("IP:");

            fis.read(ip);
            int version = (ip[0] & 0xF0) >> 4;
            int hl = (ip[0] & 0x0F) * 4;
            int tos = (ip[1] & 0xFF);
            int tl = ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
            System.out.println("IP:   Version = " + version);
            System.out.println("IP:   Header length = " + hl + " bytes");
            System.out.println("IP:   Type of service = " + String.format("0x%02x", tos));
            printTOSBits(ip[1]);
            System.out.println("IP:   Total length = " +  tl + " bytes");

            fis.read(ip);
            int id = ((ip[0] & 0xFF) << 8) | (ip[1] & 0xFF);
            int flags = (((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF));
            int fragOffset = ((((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF))) & 0xFF;
            System.out.println("IP:   Identification = " +  id);
            System.out.println("IP:   Flags = " +  String.format("0x%02x", flags));
            printfragBits(ip[2]);
            System.out.println("IP:   Fragment offset = " +  fragOffset + " bytes");

            fis.read(ip);
            int ttl = (ip[0] & 0xFF);
            int protocol = (ip[1] & 0xFF);
            String protocol_str = "";
            if (protocol == 17) {
                protocol_str = " (UDP)";
            } else if (protocol == 6) {
                protocol_str = " (TCP)";
            } else if (protocol == 1) {
                protocol_str = " (ICMP)";
            }
            int checksum = ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
            System.out.println("IP:   Time to live = " +  ttl + " seconds/hops");
            System.out.println("IP:   Protocol = " +  protocol + protocol_str);
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
            } else {
                System.out.println("IP:   There are options");
            }
            System.out.println("IP:");

            if (protocol == 6) {
                System.out.println("TCP:  ----- TCP Header -----");
                System.out.println("TCP:");
                fis.read(tcp);
                int src_port = ((tcp[0] & 0xFF) << 8) | (tcp[1] & 0xFF);
                int dst_port = ((tcp[2] & 0xFF) << 8) | (tcp[3] & 0xFF);
                System.out.println("TCP:  Source port = " + src_port);
                System.out.println("TCP:  Destination port = " + dst_port);

                fis.read(tcp);
                int seq_num = byteArrayToInt(tcp);
                System.out.println("TCP:  Sequence number = " + seq_num);

                fis.read(tcp);
                int ack_num = byteArrayToInt(tcp);
                long ack_numl = ack_num & 0x00000000ffffffffL;
                System.out.println("TCP:  Acknowledgement number = " + ack_numl);

                fis.read(tcp);
                int data_offset = (tcp[0] & 0xF0) >> 4;
                int tcp_flags = ((tcp[0] & 0xFF << 8) | (tcp[1] & 0xFF)) & 0xFF;
                int window = ((tcp[2] & 0xFF) << 8) | (tcp[3] & 0xFF);;
                System.out.println("TCP:  Data offset = " + data_offset + " bytes");
                System.out.println("TCP:  Flags = " + String.format("0x%02x", tcp_flags));
                printTCPBits(tcp_flags);
                System.out.println("TCP:  Window = " + window);

                fis.read(tcp);
                int tcp_checksum = ((tcp[0] & 0xFF) << 8) | (tcp[1] & 0xFF);
                int up = ((tcp[2] & 0xFF) << 8) | (tcp[3] & 0xFF);
                System.out.println("TCP:  Checksum = " + String.format("0x%02x", tcp_checksum));
                System.out.println("TCP:  Urgent pointer = " + up);
                System.out.println("TCP:  No options");
                System.out.println("TCP:");

                System.out.println("TCP:  Data: (first 64 bytes)");
                for (int i = 0; i < 4; i++) {
                    fis.read(data);
                    print16DataBytes(data, protocol);
                }

            } else if (protocol == 17) {
                System.out.println("UDP:  ----- UDP Header -----");
                System.out.println("UDP:");

                fis.read(udp);
                int src_port = ((udp[0] & 0xFF) << 8) | (udp[1] & 0xFF);
                int dst_port = ((udp[2] & 0xFF) << 8) | (udp[3] & 0xFF);
                System.out.println("UDP:  Source port = " + src_port);
                System.out.println("UDP:  Destination port = " + dst_port);

                fis.read(udp);
                int length = ((udp[0] & 0xFF) << 8) | (udp[1] & 0xFF);
                int udp_checksum = ((udp[2] & 0xFF) << 8) | (udp[3] & 0xFF);
                System.out.println("UDP:  Length = " + length);
                System.out.println("UDP:  Checksum = " + String.format("0x%02x", udp_checksum));

                System.out.println("UDP:");
                System.out.println("UDP:  Data: (first 64 bytes)");
                for (int i = 0; i < 4; i++) {
                    fis.read(data);
                    print16DataBytes(data, protocol);
                }
            } else if (protocol == 1) {
                System.out.println("ICMP:  ----- ICMP Header ----- ");
                System.out.println("ICMP:");

                fis.read(icmp);
                int icmp_type = icmp[0] & 0xFF;
                int code = icmp[1] & 0xFF;
                int icmp_checksum = ((icmp[2] & 0xFF) << 8) | (icmp[3] & 0xFF);
                System.out.println("ICMP:  Type = " + icmp_type + " (Echo request)");
                System.out.println("ICMP:  Code = " + code);
                System.out.println("ICMP:  Checksum = " + String.format("0x%02x", icmp_checksum));
                System.out.println("ICMP:");
            }

            fis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
