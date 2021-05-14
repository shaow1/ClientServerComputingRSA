/**
 * Author: Wangning Shao
 * Last Modified: March 5th 2021
 *
 * This program demonstrates a very simple TCP server with RSA Signature verification.
 * When the server get the requested it will verify user's identity then perform operation
 * user requested
 * and send the result back to client
 */
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;

public class VerifyingServerTCP {

    public static Map<String, String> users = new TreeMap<>();
    /**
     * No command line arguments needed.
     */
    public static void main(String args[]) {
        // define a TCP style socket
        Socket clientSocket = null;
        try {
            // the server port we are using
            int serverPort = 7777;
            // Create a new server socket
            ServerSocket listenSocket = new ServerSocket(serverPort);

            /*
             * Forever,
             *   read a line from the socket
             *   print it to the console
             *   echo it (i.e. write it) back to the client
             */
            while (true) {
                /*
                 * Block waiting for a new connection request from a client.
                 * When the request is received, "accept" it, and the rest
                 * the tcp protocol handshake will then take place, making
                 * the socket ready for reading and writing.
                 */
                // Connect to a client.
                clientSocket = listenSocket.accept();
                // Set up "in" to read from the client socket
                Scanner in;
                in = new Scanner(clientSocket.getInputStream());

                // Set up "out" to write to the client socket
                PrintWriter out;
                out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));
                // read data coming from client side
                String command = in.nextLine();
                //precheck public key hash to the ID and signature matches
                // if failed send "Error in request!" otherwise proceed calculation
                if(!preCheck(command))
                {
                    //send result back to client
                    out.println("Error in request!");
                    out.flush();
                }
                else
                {
                    //Split user command into operation 0, id 1, value 2
                    String[] fromClient = command.split(",");
                    //Check if the operation is addition
                    if(fromClient[4].equals("1"))
                    {
                        //If the server receives an ID that it has not seen before, that ID will initially be associated with a sum of 0.
                        if(!users.containsKey(fromClient[0]))
                        {
                            users.put(fromClient[0], "0");
                        }
                        //perform addition and assign value back to correct id in TreeMap
                        users.put(fromClient[0],String.valueOf(add(Integer.parseInt(fromClient[2]), Integer.parseInt(users.get(fromClient[0])))));
                    }
                    //Check if the operation is subtraction
                    else if(fromClient[4].equals("2"))
                    {
                        //If the server receives an ID that it has not seen before, that ID will initially be associated with a sum of 0.
                        if(!users.containsKey(fromClient[0]))
                        {
                            users.put(fromClient[0], "0");
                        }
                        //perform subtraction and assign value back to correct id in TreeMap
                        users.put(fromClient[0],String.valueOf(subtract(Integer.parseInt(fromClient[2]), Integer.parseInt(users.get(fromClient[0])))));
                    }
                    //Check if the operation is view
                    else if(fromClient[4].equals("3"))
                    {
                        //If the server receives an ID that it has not seen before, that ID will initially be associated with a sum of 0.
                        if(!users.containsKey(fromClient[0]))
                        {
                            users.put(fromClient[0], "0");
                        }
                    }
                    //send result back to client
                    out.println(users.get(fromClient[0]));
                    out.flush();
                }

            }

        // Handle IOExceptions
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());

        // If quitting (typically by you sending quit signal) clean up sockets
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                // ignore exception on close
            }
        }
    }

    /**
     * @param i, an integer which user provides and current sum
     * @param result, an integer that represent current sum
     * return the result
     */
    public static int add(int i, int result)
    {
        //Add value get from client to current result
        result += i;
        //return final result
        return result;
    }
    /**
     * @param i, an integer which user provides and current sum
     * @param result, an integer that represent current sum
     * return the result
     */
    public static int subtract(int i, int result)
    {
        //Subtract value get from client to current sum
        result -= i;
        //return final result
        return result;
    }

    public static boolean preCheck(String message)throws Exception
    {
        //Split values received from client by ,
        String[] fromClient = message.split(",");
        //Split n and e using ; we inserted
        String[] keys = fromClient[1].split(";");
        //Assign corresponding values to e and n
        BigInteger e = new BigInteger(keys[0]);
        BigInteger n = new BigInteger(keys[1]);
        //first element in fromClient array is user ID
        String id = fromClient[0];
        //third element in fromClient array is operand user provided
        String value = fromClient[2];
        //fourth element in fromClient array is the operation user provided
        String operation = fromClient[4];
        //Create a message which will be used to check user's signature
        String messageToCheck = String.valueOf(id) + e + ";" + n + value + operation;
        //generate composite keys with e and n
        String input = e.toString() + n.toString();
        // compute the digest with SHA-256
        byte[] bytesOfMessage = input.getBytes("UTF-8");
        MessageDigest md1 = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md1.digest(bytesOfMessage);
        // create byte array to hold last 20 byte
        byte[] last20Byte = new byte[20];
        //loop through last 20 items
        for(int i = bigDigest.length-20; i < bigDigest.length;i++ )
        {
            last20Byte[i-(bigDigest.length-20)] =  bigDigest[i];
        }
        //Convert byte array into string
        String checkID = DatatypeConverter.printHexBinary(last20Byte).toLowerCase();
        //Check whether id we received from message and the one we compute are the same
        if(!checkID.equals(id))
        {
            return false;
        }

        // Take the encrypted string and make it a big integer
        BigInteger encryptedHash = new BigInteger(fromClient[3]);

        // Decrypt it
        BigInteger decryptedHash = encryptedHash.modPow(e, n);

        // Get the bytes from messageToCheck
        byte[] bytesOfMessageToCheck = messageToCheck.getBytes("UTF-8");

        // compute the digest of the message with SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageToCheckDigest = md.digest(bytesOfMessageToCheck);

        // messageToCheckDigest is a full SHA-256 digest
        // take two bytes from SHA-256 and add a zero byte
        byte[] extraByte = new byte[3];
        extraByte[0] = 0;
        extraByte[1] = messageToCheckDigest[0];
        extraByte[2] = messageToCheckDigest[1];

        // Make it a big int
        BigInteger bigIntegerToCheck = new BigInteger(extraByte);

        // inform the client on how the two compare
        // if message we generate match the one is signed
        // the message is send from trust client
        if(bigIntegerToCheck.compareTo(decryptedHash) == 0)
        {
            return true;
        }
        else {
            return false;
        }
    }
}