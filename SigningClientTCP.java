/**
 * Author: Wangning Shao
 * Last Modified: March 5th 2021
 *
 * This program demonstrates a very simple TCP client with RSA Signature.
 * The command line is packaged and placed in a single TCP packet.
 * The packet is sent to the server asynchronously.
 * The program then blocks waiting for the server to perform
 * the requested operation. When the response packet arrives,
 * a String object is created and the reply is displayed.
 * The program illustrates separate concerns and "proxy design"
 */
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Random;

public class SigningClientTCP {
    /**
     * No command line arguments needed.
     */
    public static void main(String args[]) {
        try {
            //Variable will be used to store user input into bufferReader
            BufferedReader typed = new BufferedReader(new InputStreamReader(System.in));
            String operation;
            //Call generateNED to generate public and private key using RSA
            BigInteger[] ned = generateNED();
            //keep client open
            while (true) {
                //Print out menus
                System.out.println("1. Add a value to your sum.");
                System.out.println("2. Subtract a value from your sum.");
                System.out.println("3. View your sum.");
                System.out.println("4. Exit client.");
                //get user input
                operation = typed.readLine();

                //Check user input whether or not user want to stop client
                //Announce "Client side quitting."
                if (operation.equals("4")) {
                    System.out.println("Client side quitting. The remote variable server is still running.");
                    System.exit(0);
                }
                //if user wants to perform add operation
                else if(operation.equals("1")) {
                    System.out.println("Enter value to add: ");
                    //get value user provided
                    String value = typed.readLine();
                    //Convert last 20 byte of client's public key into string
                    String id = DatatypeConverter.printHexBinary(last20(ned)).toLowerCase();
                    //Prepare public keys need for decryption, separate e and n with ;
                    String keyComb = ned[1].toString() + ";" + ned[0].toString();
                    //Sign the message which include user ID, public keys(n, e), operand (user input value)
                    // operation user choose and n,e,d
                    String signedVal = sign(id + keyComb + value + operation, ned);
                    //compose command will send to server with signed value
                    String command = id + "," + keyComb + "," + value + "," + signedVal + "," + operation;
                    // assign return value from server to result
                    String result = operation(command);
                    if(!result.equals("Error in request!"))
                    {
                        //Show the result to the client
                        System.out.println("The result is " + result + ".");
                    }
                    else
                    {
                        //Show error message "Error in request!"
                        System.out.println(result);
                    }
                }
                //if user wants to perform subtraction operation
                else if(operation.equals("2")) {
                    System.out.println("Enter value to subtract: ");
                    //get value user provided
                    String value = typed.readLine();

                    //Convert last 20 byte of client's public key into string
                    String id = DatatypeConverter.printHexBinary(last20(ned)).toLowerCase();
                    //Prepare public keys need for decryption, separate e and n with ;
                    String keyComb = ned[1].toString() + ";" + ned[0].toString();
                    //Sign the message which include user ID, public keys(n, e), operand (user input value)
                    // operation user choose and n,e,d
                    String signedVal = sign(id + keyComb + value + operation, ned);
                    //compose command will send to server with signed value
                    String command = id + "," + keyComb + "," + value + "," + signedVal + "," + operation;
                    // assign return value from server to result
                    String result = operation(command);
                    if(!result.equals("Error in request!"))
                    {
                        //Show the result to the client
                        System.out.println("The result is " + result + ".");
                    }
                    else
                    {
                        //Show error message "Error in request!"
                        System.out.println(result);
                    }
                }
                //if user wants to view record
                else if(operation.equals("3")) {
                    //Convert last 20 byte of client's public key into string
                    String id = DatatypeConverter.printHexBinary(last20(ned)).toLowerCase();
                    //Prepare public keys need for decryption, separate e and n with ;
                    String keyComb = ned[1].toString() + ";" + ned[0].toString();
                    //Sign the message which include user ID, public keys(n, e), operand (user input value)
                    // operation user choose and n,e,d
                    String signedVal = sign(id + keyComb + "value" + operation, ned);
                    //compose command will send to server with signed value
                    String command = id + "," + keyComb + "," + "value" + "," + signedVal + "," + operation;
                    // assign return value from server to result
                    String result = operation(command);
                    //Show the result to the client
                    System.out.println("The result is " + result + ".");
                }
            }
        // handle IOException
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());
        // handle all other IOExceptions
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @param command, a map which contains all user input
     *  return the result received from server
     */
    public static String operation(String command) throws IOException {
        // define a TCP style socket
        Socket clientSocket = null;
        // Set up "in" to read data send back from server
        BufferedReader in;
        // Set up "out" to write to the Server socket
        PrintWriter out;
        String fromServer;
        try {
            int serverPort = 7777;
            // build the socket holding the destination address and port
            clientSocket = new Socket("localhost", serverPort);
            // build inputStream
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            //build outputStreamWriter
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));
            //send user command to server
            out.println(command);
            out.flush();
            // read a line of data send back from server
            fromServer = in.readLine();
            // always close the socket
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                // ignore exception on close
            }
        }
        //Return the addition result
        return fromServer;
    }

    /**
     * Below code is separated from Professor's RSAExample
     *  return value for n
     */
    public static BigInteger[] generateNED()
    {
        BigInteger[] ned = new BigInteger[3];
        // Each public and private key consists of an exponent and a modulus
        BigInteger n; // n is the modulus for both the private and public keys
        BigInteger e; // e is the exponent of the public key
        BigInteger d; // d is the exponent of the private key
        Random rnd = new Random();
        // Step 1: Generate two large random primes.
        // We use 400 bits here, but best practice for security is 2048 bits.
        // Change 400 to 2048, recompile, and run the program again and you will
        // notice it takes much longer to do the math with that many bits.
        BigInteger p = new BigInteger(400, 100, rnd);
        BigInteger q = new BigInteger(400, 100, rnd);

        // Step 2: Compute n by the equation n = p * q.
        n = p.multiply(q);

        // Step 3: Compute phi(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Step 4: Select a small odd integer e that is relatively prime to phi(n).
        // By convention the prime 65537 is used as the public exponent.
        e = new BigInteger("65537");
        // Step 5: Compute d as the multiplicative inverse of e modulo phi(n).
        d = e.modInverse(phi);
        //assign BigInteger values n,e,d to BigInteger[] ned with index 0,1,2
        ned[0] = n;
        ned[1] = e;
        ned[2] = d;
        return ned;
    }

    /**
     * Signing proceeds as follows:
     * 1) Get the bytes from the string to be signed.
     * 2) Compute a SHA-1 digest of these bytes.
     * 3) Copy these bytes into a byte array that is one byte longer than needed.
     *    The resulting byte array has its extra byte set to zero. This is because
     *    RSA works only on positive numbers. The most significant byte (in the
     *    new byte array) is the 0'th byte. It must be set to zero.
     * 4) Create a BigInteger from the byte array.
     * 5) Encrypt the BigInteger with RSA d and n.
     * 6) Return to the caller a String representation of this BigInteger.
     * @param message a sting to be signed
     * @param ned a BigInteger array which hold n,e,d
     * @return a string representing a big integer - the encrypted hash.
     * @throws Exception
     */
    public static String sign(String message,BigInteger[] ned) throws Exception {

        // compute the digest with SHA-256
        byte[] bytesOfMessage = message.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md.digest(bytesOfMessage);

        // we only want two bytes of the hash for ShortMessageSign
        // we add a 0 byte as the most significant byte to keep
        // the value to be signed non-negative.
        byte[] messageDigest = new byte[3];
        messageDigest[0] = 0;   // most significant set to 0
        messageDigest[1] = bigDigest[0]; // take a byte from SHA-256
        messageDigest[2] = bigDigest[1]; // take a byte from SHA-256

        // The message digest now has three bytes. Two from SHA-256
        // and one is 0.

        // From the digest, create a BigInteger
        BigInteger m = new BigInteger(messageDigest);

        // encrypt the digest with the private key
        BigInteger c = m.modPow(ned[2], ned[0]);

        // return this as a big integer string
        return c.toString();
    }
    /**
     * Below method will be used to generate last20 Byte of the
     * hash of client's public key
     * @param ned a BigInteger array which hold n,e,d
     * @return a byte array which contains last 20 byte of e and n
     * @throws Exception
     */
    public static byte[] last20 (BigInteger[] ned) throws Exception {
        String input = ned[1].toString() + ned[0].toString();
        // compute the digest with SHA-256
        byte[] bytesOfMessage = input.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md.digest(bytesOfMessage);
        // create byte array to hold last 20 byte
        byte[] last20Byte = new byte[20];
        //loop through last 20 items
        for(int i = bigDigest.length-20; i < bigDigest.length;i++ )
        {
            last20Byte[i-(bigDigest.length-20)] =  bigDigest[i];
        }
        // return the last 20 byte from the key we build
        return last20Byte;
    }
}