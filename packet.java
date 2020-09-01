import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class packet
{   
    // Program parameters.
    private static final int  P_NUM_ICMP     = 1;
    private static final int  P_NUM_TCP      = 6;
    private static final int  P_NUM_UDP      = 17;
    private static final int  DATA_SIZE      = 64;

    // Bit masks for converting signed types to unsigned.
    private static final int  BIT_MASK_CHAR  = 0xFF;
    private static final int  BIT_MASK_SHORT = 0xFFFF;
    private static final long BIT_MASK_LONG  = 0xFFFFFFFFL;

    // Packet Properties.
    private int    packet_size;
    private String packet_type;

    // Ether Header
    private byte[] ether_dhost = new byte[6];
    private byte[] ether_shost = new byte[6];
    private byte[] ether_type  = new byte[2];
    
    // IP Header
    private int    ip_ver;
    private int    ip_hlen;
    private byte   ip_tos;
    private int    ip_len;
    private int    ip_id;
    private int[]  ip_frag     = new int[2];
    private int    ip_off;
    private int    ip_ttl;
    private int    ip_p;
    private byte[] ip_check    = new byte[2];
    private byte[] ip_src      = new byte[4];
    private byte[] ip_dest     = new byte[4];

    // ICMP Header
    private int    icmp_type;
    private int    icmp_code;
    private byte[] icmp_check  = new byte[2];

    // TCP Header
    private int    tcp_sport;
    private int    tcp_dport;
    private long   tcp_seq_n;
    private long   tcp_ack_n;
    private byte[] tcp_off     = new byte[1];
    private byte[] tcp_flags   = new byte[1];
    private int    tcp_win;
    private byte[] tcp_check   = new byte[2];
    private int    tcp_up;
    private byte[] tcp_data;

    // UDP Header
    private int    udp_sport;
    private int    udp_dport;
    private int    udp_len;
    private byte[] udp_check   = new byte[2];
    private byte[] udp_data;
    
    private void parseICMP(ByteBuffer bb)
    {
        icmp_type = bb.get() & BIT_MASK_CHAR;
        icmp_code = bb.get() & BIT_MASK_CHAR;
        bb.get(icmp_check);
    }

    private void parseTCP(ByteBuffer bb)
    {
        // Record start of header position.
        int header_pos = bb.position();
        
        tcp_sport = bb.getShort() & BIT_MASK_SHORT;
        tcp_dport = bb.getShort() & BIT_MASK_SHORT;

        // Although ints (4 bytes), implicitly casting to longs by
        // bitwise AND-ing with long bit mask. Int might have not
        // been able to hold full values, gave odd result. (long fixes)
        tcp_seq_n = bb.getInt()   & BIT_MASK_LONG;
        tcp_ack_n = bb.getInt()   & BIT_MASK_LONG;

        bb.get(tcp_off);
        bb.get(tcp_flags);

        tcp_win   = bb.getShort() & BIT_MASK_SHORT;

        bb.get(tcp_check);

        tcp_up    = bb.getShort() & BIT_MASK_SHORT; 
        
        // Move position of ByteBuffer to start of header and store
        // first 64 bytes.
        bb.position(header_pos);
        
        // Allocate appropriate amount of data to store first 64 bytes of data.
        // Allocates less if not enough data.
        tcp_data = new byte[Math.min(DATA_SIZE, packet_size - header_pos)];
        bb.get(tcp_data);
    }
    
    private void parseUDP(ByteBuffer bb)
    {
        // Record start of header position.
        int header_pos = bb.position();

        udp_sport = bb.getShort() & BIT_MASK_SHORT;
        udp_dport = bb.getShort() & BIT_MASK_SHORT;
        udp_len   = bb.getShort() & BIT_MASK_SHORT;
        bb.get(udp_check);

        // Move position of ByteBuffer to start of header.
        bb.position(header_pos);

        // Allocate appropriate amount of memory to store first 64 bytes of data.
        // Allocates less if not enough data.
        udp_data = new byte[Math.min(DATA_SIZE, packet_size - header_pos)];
        bb.get(udp_data);
    }
    
    private int getBit(int val, int pos)
    {
        // Get single bit value at specified position.
        return (val >>> pos) & 1;
    }

    private void parse(ByteBuffer bb)
    {
        packet_size = bb.limit();

        // Parse Ether Header.
        bb.get(ether_dhost);
        bb.get(ether_shost);
        bb.get(ether_type);
        
        // Parse IP Header.
        // Get byte containing version and header length and parse.
        byte vhl = bb.get();
        ip_ver   = vhl >>> 4;
        ip_hlen  = (vhl & 0x0F) * 4;

        ip_tos   = bb.get();
        ip_len   = bb.getShort() & BIT_MASK_SHORT;
        ip_id    = bb.getShort() & BIT_MASK_SHORT;
        ip_off   = bb.getShort() & BIT_MASK_SHORT;
        ip_ttl   = bb.get()      & BIT_MASK_CHAR;
        ip_p     = bb.get()      & BIT_MASK_CHAR;
        
        // Get fragment bits, or the first 3 bits from ip_off.
        // Only the last two of the three bits actually matter.
        ip_frag[0] = getBit(ip_off, 14);
        ip_frag[1] = getBit(ip_off, 13);

        bb.get(ip_check); 
        bb.get(ip_src);
        bb.get(ip_dest);

        // Parse ICMP/TCP/UDP Header.
        switch( ip_p )
        {
            case P_NUM_ICMP : parseICMP(bb);
                packet_type = "ICMP";
                break;
            
            case P_NUM_TCP  : parseTCP(bb);
                packet_type = "TCP";
                break;

            case P_NUM_UDP  : parseUDP(bb);
                packet_type = "UDP";
                break;

            default : System.out.format("Unknown protocol: %s\n", ip_p);
                break;
        }
    }
    
    private static void bytesToHex(byte[] bytes) {
        String text = new String(bytes, StandardCharsets.US_ASCII).replaceAll("\\P{Print}", ".");

        System.out.println("Pos   Hex  Dec");

        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;

            // Also can use Integer.toHexString() to get hex.
            System.out.format("%3d  0x%02X  %3d %c\n", j, v, v, text.charAt(j));
        }
        System.out.println();
    }

    private String frmtByte(byte[] bytes, String delim, String format)
    {
        String arr[] = new String[bytes.length];
        for( int i = 0; i < bytes.length; i++ )
            arr[i] = String.format(format, bytes[i] & 0xFF);

        return String.join(delim, arr);
    }

    private String frmtByte(byte[] bytes)
    {
        String hex_val = "0x";

        for( int i = 0; i < bytes.length; i++ )
            hex_val += String.format("%02x", bytes[i]);

        return hex_val;
    }

    public void print()
    {   
        String ether    = "ETHER:  ";
        String ip       = "IP:     ";
        String endl     = "\n";
        String frag_msg = ip_frag[0] == 1 ? "do not fragment" : "OK to fragment";
        
        // Print Ether header.
        System.out.println
            (
                ether + "----- Ether Header -----" + endl
              + ether + endl
              + ether + "Packet size = " + packet_size + " bytes" + endl
              + ether + "Destination = " + frmtByte(ether_dhost, ":", "%02x") + "," + endl
              + ether + "Source      = " + frmtByte(ether_shost, ":", "%02x") + "," + endl
              + ether + "Ethertype   = " + frmtByte(ether_type, "", "%02x") + " (IP)" + endl
              + ether 
            );
        
        // Print IP header.
        System.out.println
            (
                ip + "----- IP Header -----" + endl
              + ip + endl
              + ip + "Version = " + ip_ver + endl
              + ip + "Header Length = " + ip_hlen + endl
              + ip + "Type of service = " + String.format("0x%02x", ip_tos) + endl
              + ip + String.format("      xxx. .... = %d (precedence)", 0) + endl
              + ip + String.format("      ...%d .... = ", 0) + endl
              + ip + String.format("      .... %d... = ", 0) + endl
              + ip + String.format("      .... .%d.. = ", 0) + endl
              + ip + "Total length = " + ip_len + " bytes" + endl
              + ip + "Identification = " + ip_id + endl
              + ip + "Flags = " + endl
              + ip + String.format("      .%d.. .... = %s", ip_frag[0], frag_msg) + endl
              + ip + String.format("      ..%d. .... = %s", ip_frag[1], "last fragment") + endl
              + ip + "Fragment offset = " + ip_off + " bytes" + endl
              + ip + "Time to live = " + ip_ttl + " seconds/hops" + endl
              + ip + "Protocol = " + ip_p + String.format(" (%s)", packet_type) + endl
              + ip + "Header checksum = " + frmtByte(ip_check) + endl
              + ip + "Source address = " + frmtByte(ip_src, ".", "%d") + endl
              + ip + "Destination address = " + frmtByte(ip_dest, ".", "%d") + endl
              + ip + "No options" + endl
              + ip
            );
    }

    public packet(byte[] bytes)
    {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        parse(bb);
    }
}
