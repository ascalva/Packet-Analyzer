import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.ArrayIndexOutOfBoundsException;
import java.nio.charset.StandardCharsets;

// TODO: Seperate main program from analyzer (might not work since class needs to be called
//       from command line).
//
public class pktanalyzer {
    
    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes();

    // Might make byte array into class attribute.
    // private byte packet[] = null;

    private void parse()
    {
        // Start parsing byte array, figure out what type of packet it is.
    }
    
    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];

        for (int j = 0; j < bytes.length; j++) {
            int v               = bytes[j] & 0xFF;
            hexChars[j * 2]     = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];

            System.out.format("Byte pos %3d: 0x%-2s %4d\n", j, Integer.toHexString(v), v);
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {

        File packet_file      = null;
        FileInputStream s_bin = null;
        byte packet[]         = null;
        
        // Read in file as byte array.
        try 
        {   
            // Create file object using user-defined file.
            packet_file = new File(args[0]);

            // Create FileInputStream object.
            s_bin = new FileInputStream(packet_file);
            
            // Allocate enough space to hold byte file.
            packet = new byte[(int) packet_file.length()];
            
            // Read bytes to array.
            s_bin.read(packet);
            
            // DEBUG: Print string form of byte array
            String s = new String(packet);
            System.out.println(s);

            bytesToHex(packet);
        }

        catch( ArrayIndexOutOfBoundsException oobe )
        {
            System.out.println("Not enough command line arguments provided: " + oobe);
        }

        catch( FileNotFoundException fnfe )
        {
            System.out.println("File not found" + fnfe);
        }

        catch( IOException ioe )
        {
            System.out.println("Exception while reading file" + ioe);
        }
        
        // Cleanup and close file stream.
        finally
        {
            try
            {
                if( s_bin != null )
                    s_bin.close();
            }

            catch( IOException ioe )
            {
                System.out.println("Exception" + ioe);
            }
        }
    }
}
