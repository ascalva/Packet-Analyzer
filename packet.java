import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class packet
{   
    // System parameters.
    private static final int P_NUM_ICMP = 1;
    private static final int P_NUM_TCP  = 6;
    private static final int P_NUM_UDP  = 17;

    // Ether Header
    private byte[] ether_dhost = new byte[6];
    private byte[] ether_shost = new byte[6];
    private byte[] ether_type  = new byte[2];
    
    // IP Header
    private byte[] ip_vhl      = new byte[1];
    private byte[] ip_tos      = new byte[1];
    private int    ip_len;
    private int    ip_id;
    private int    ip_os;
    private int    ip_ttl;
    private int    ip_p;
    private byte[] ip_cs       = new byte[2];
    private byte[] ip_src      = new byte[4];
    private byte[] ip_dest     = new byte[4];

    // ICMP Header
    private int    icmp_type;
    private int    icmp_code;
    private byte[] icmp_cs     = new byte[2];

    // TCP Header
    private int    tcp_sport;
    private int    tcp_dport;
    private int    tcp_seq_n;
    private int    tcp_ack_n;
    private int    tcp_off;

    // UDP Header
    private int    udp_sport;
    private int    udp_dport;
    private int    udp_len;
    private byte[] udp_cs      = new byte[2];
    

    private void parseICMP(ByteBuffer bb)
    {
        System.out.println("Parsing ICMP Header");

        icmp_type = bb.get() & 0xFF;
        icmp_code = bb.get() & 0xFF;
        bb.get(icmp_cs);

        // DEBUG
        System.out.println(icmp_type);
        System.out.println(icmp_code);
        bytesToHex(icmp_cs);
    }

    private void parseTCP(ByteBuffer bb)
    {
        System.out.println("Parsing TCP Header");
        
        tcp_sport = bb.getShort() & 0xFFFF;
        tcp_dport = bb.getShort() & 0xFFFF;
        tcp_seq_n = bb.getInt()   & 0xFFFFFFFF;
        tcp_ack_n = bb.getInt()   & 0xFFFFFFFF;

        // DEBUG
        System.out.println(tcp_sport);
        System.out.println(tcp_dport);
        System.out.println(tcp_seq_n);
        System.out.println(tcp_ack_n);

    }
    
    private void parseUDP(ByteBuffer bb)
    {
        System.out.println("Parsing UDP Header");

        udp_sport = bb.getShort() & 0xFFFF;
        udp_dport = bb.getShort() & 0xFFFF;
        udp_len   = bb.getShort() & 0xFFFF;
        bb.get(udp_cs);

        // DEBUG
        System.out.println(udp_sport);
        System.out.println(udp_dport);
        System.out.println(udp_len);
        bytesToHex(udp_cs);
    }

    private void parse(ByteBuffer bb)
    {
        // Parse Ether Header.
        bb.get(ether_dhost);
        bb.get(ether_shost);
        bb.get(ether_type);
        
        // Parse IP Header.
        bb.get(ip_vhl); 
        bb.get(ip_tos);

        ip_len = bb.getShort() & 0xFFFF;
        ip_id  = bb.getShort() & 0xFFFF;
        ip_os  = bb.getShort() & 0xFFFF;
        ip_ttl = bb.get()      & 0xFF;
        ip_p   = bb.get()      & 0xFF;

        bb.get(ip_cs); 
        bb.get(ip_src);
        bb.get(ip_dest);

        // Parse ICMP/TCP/UDP Header.
        switch( ip_p )
        {
            case P_NUM_ICMP : parseICMP(bb);
                break;
            
            case P_NUM_TCP  : parseTCP(bb);
                break;

            case P_NUM_UDP  : parseUDP(bb);
                break;

            default : System.out.format("Unknown protocol: %s\n", ip_p);
                break;
        }
    }
    
    public static void bytesToHex(byte[] bytes) {
        String text = new String(bytes, StandardCharsets.US_ASCII).replaceAll("\\P{Print}", ".");

        System.out.println("Pos   Hex  Dec");

        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;

            // Also can use Integer.toHexString() to get hex.
            System.out.format("%3d  0x%02X  %3d %c\n", j, v, v, text.charAt(j));
        }
        System.out.println();
    }

    public packet(byte[] bytes)
    {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        parse(bb);
    }
}
