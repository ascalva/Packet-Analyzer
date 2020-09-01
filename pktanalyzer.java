import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.ArrayIndexOutOfBoundsException;

public class pktanalyzer 
{
    public static void main(String[] args) {
        File packet_file      = null;
        FileInputStream s_bin = null;
        byte packet_bin[]     = null;
        
        // Read in file as byte array.
        try 
        {   
            // Create file object using user-defined file.
            packet_file = new File(args[0]);

            // Create FileInputStream object.
            s_bin = new FileInputStream(packet_file);
            
            // Allocate enough space to hold byte file.
            packet_bin = new byte[(int) packet_file.length()];
            
            // Read bytes to array.
            s_bin.read(packet_bin);
                
            // Create packet object to parse byte array.
            packet p_obj = new packet(packet_bin);

            // Print packet contents and analysis.
            p_obj.print();
        }
        
        // Error if user doesn't provide any arguments.
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
