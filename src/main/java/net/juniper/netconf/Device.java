/*
 Copyright (c) 2013 Juniper Networks, Inc.
 All Rights Reserved

 Use is subject to license terms.
*/

package net.juniper.netconf;

import lombok.extern.slf4j.Slf4j;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile;
import net.schmizz.sshj.userauth.method.AuthPublickey;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

/**
 * A <code>Device</code> is used to define a Netconf server.
 * <p>
 * Typically, one
 * <ol>
 * <li>creates a {@link #Device(String, String, String, String) Device}
 * object.</li>
 * <li>perform netconf operations on the Device object.</li>
 * <li>If needed, call the method createNetconfSession() to create another
 * NetconfSession.</li>
 * <li>Finally, one must close the Device and release resources with the
 * {@link #close() close()} method.</li>
 * </ol>
 */
@Slf4j
public class Device {

    private String hostName;
    private String userName;
    private String password;
    private String helloRpc;
    private String pemKeyFile;
    private boolean keyBasedAuthentication;
    private SSHClient sshClient;
    private int port;
    private int timeout;
    private DocumentBuilder builder;
    private NetconfSession defaultSession;

    private static final int DEFAULT_TIMEOUT_MILLISECONDS = 5000;
    private static final int DEFAULT_NETCONF_PORT = 830;

    /**
     * Prepares a new <code>Device</code> object, with default client
     * capabilities and default port 830, which can then be used to perform
     * netconf operations.
     * <p>
     *
     * @throws ParserConfigurationException when the configuration cannot be parsed.
     */
    public Device() throws ParserConfigurationException {
        keyBasedAuthentication = false;
        helloRpc = defaultHelloRPC();
        port = DEFAULT_NETCONF_PORT;
        timeout = DEFAULT_TIMEOUT_MILLISECONDS;
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        builder = factory.newDocumentBuilder();
    }


    /**
     * Prepares a new <code>Device</code> object, with default client
     * capabilities and default port 830, which can then be used to perform
     * netconf operations.
     * <p>
     *
     * @param hostName   the hostname of the Netconf server.
     * @param userName   the login username of the Netconf server.
     * @param password   the login password of the Netconf server.
     * @param pemKeyFile path of the file containing RSA/DSA private key, in PEM
     *                   format. For user-password based authentication, let this be
     *                   null.
     * @throws ParserConfigurationException when the configuration cannot be parsed.
     */
    public Device(String hostName, String userName, String password,
                  String pemKeyFile) throws
            ParserConfigurationException {
        this.hostName = hostName;
        this.userName = userName;
        this.password = password;
        this.pemKeyFile = pemKeyFile;
        keyBasedAuthentication = pemKeyFile != null;
        helloRpc = defaultHelloRPC();
        port = DEFAULT_NETCONF_PORT;
        timeout = DEFAULT_TIMEOUT_MILLISECONDS;
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        builder = factory.newDocumentBuilder();
    }

    /**
     * Prepares a new <code>Device</code> object, with default client
     * capabilities and user-defined port which can then be used to perform
     * netconf operations.
     * <p>
     *
     * @param hostName   the hostname of the Netconf server.
     * @param userName   the login username of the Netconf server.
     * @param password   the login password of the Netconf server.
     * @param pemKeyFile path of the file containing RSA/DSA private key, in PEM
     *                   format. For user-password based authentication, let this be
     *                   null.
     * @param port       port number to establish Netconf session over SSH-2.
     * @throws ParserConfigurationException when the configuration cannot be parsed.
     */
    public Device(String hostName, String userName, String password,
                  String pemKeyFile, int port)
            throws ParserConfigurationException {
        this.hostName = hostName;
        this.userName = userName;
        this.password = password;
        this.pemKeyFile = pemKeyFile;
        keyBasedAuthentication = pemKeyFile != null;
        helloRpc = defaultHelloRPC();
        this.port = port;
        timeout = DEFAULT_TIMEOUT_MILLISECONDS;
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        builder = factory.newDocumentBuilder();
    }

    /**
     * Prepares a new <code>Device</code> object, with user-defined client
     * capabilities and default port 830 which can then be used to perform
     * netconf operations.
     * <p>
     *
     * @param hostName     the hostname of the Netconf server.
     * @param userName     the login username of the Netconf server.
     * @param password     the login password of the Netconf server.
     * @param pemKeyFile   path of the file containing RSA/DSA private key, in PEM
     *                     format. For user-password based authentication, let this be
     *                     null.
     * @param capabilities the client capabilities to be advertised to Netconf server.
     * @throws ParserConfigurationException when the configuration cannot be parsed.
     */
    public Device(String hostName, String userName, String password,
                  String pemKeyFile, List<String> capabilities) throws
            ParserConfigurationException {
        this.hostName = hostName;
        this.userName = userName;
        this.password = password;
        this.pemKeyFile = pemKeyFile;
        keyBasedAuthentication = pemKeyFile != null;
        helloRpc = createHelloRPC(capabilities);
        port = DEFAULT_NETCONF_PORT;
        timeout = DEFAULT_TIMEOUT_MILLISECONDS;
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        builder = factory.newDocumentBuilder();
    }

    /**
     * Prepares a new <code>Device</code> object, with user-defined client
     * capabilities and user-defined port which can then be used to perform
     * netconf operations.
     * <p>
     *
     * @param hostName     the hostname of the Netconf server.
     * @param userName     the login username of the Netconf server.
     * @param password     the login password of the Netconf server.
     * @param pemKeyFile   path of the file containing RSA/DSA private key, in PEM
     *                     format. For user-password based authentication, let this be
     *                     null.
     * @param port         port number to establish Netconf session over SSH-2.
     * @param capabilities the client capabilities to be advertised to Netconf server.
     * @throws ParserConfigurationException when the configuration cannot be parsed.
     */
    public Device(String hostName, String userName, String password,
                  String pemKeyFile, int port, List<String> capabilities) throws
            ParserConfigurationException {
        this.hostName = hostName;
        this.userName = userName;
        this.password = password;
        this.pemKeyFile = pemKeyFile;
        keyBasedAuthentication = pemKeyFile != null;
        helloRpc = createHelloRPC(capabilities);
        this.port = port;
        timeout = DEFAULT_TIMEOUT_MILLISECONDS;
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        builder = factory.newDocumentBuilder();
    }

    private String defaultHelloRPC() {
        List<String> defaultCap = getDefaultClientCapabilities();
        return createHelloRPC(defaultCap);
    }

    private String createHelloRPC(List<String> capabilities) {
        StringBuilder helloRPC = new StringBuilder();
        helloRPC.append("<hello>\n");
        helloRPC.append("<capabilities>\n");
        for (Object o : capabilities) {
            String capability = (String) o;
            helloRPC
                    .append("<capability>")
                    .append(capability)
                    .append("</capability>\n");
        }
        helloRPC.append("</capabilities>\n");
        helloRPC.append("</hello>\n");
        helloRPC.append("]]>]]>\n");
        return helloRPC.toString();
    }

    /**
     * Connect to the Device, and establish a default NETCONF session.
     *
     * @throws NetconfException if there are issues communicating with the Netconf server.
     */
    public void connect() throws NetconfException, UnknownHostException {
        if (hostName == null || userName == null || (password == null &&
                pemKeyFile == null)) {
            throw new NetconfException("Login parameters of Device can't be " +
                    "null.");
        }
        defaultSession = this.createNetconfSession();
    }

    /**
     * Set the timeout value for connecting to the Device.
     *
     * @param timeout timeout in milliseconds.
     */
    public void setTimeOut(int timeout) throws NetconfException {
        if (isConnected()) {
            throw new NetconfException("Can't change timeout on a live device."
                    + "Close the device first.");
        }
        this.timeout = timeout;
    }

    /**
     * Set the hostname of the Netconf server.
     *
     * @param hostName hostname of the Netconf server, to be set.
     */
    public void setHostname(String hostName) throws NetconfException {
        if (isConnected()) {
            throw new NetconfException("Can't change hostname on a live device."
                    + "Close the device first.");
        }
        this.hostName = hostName;
    }

    /**
     * Set the username of the Netconf server.
     *
     * @param userName username of the Netconf server, to be set.
     */
    public void setUserName(String userName) throws NetconfException {
        if (isConnected()) {
            throw new NetconfException("Can't change username on a live device."
                    + "Close the device first.");
        }
        this.userName = userName;
    }

    /**
     * Set the password of the Netconf server.
     *
     * @param password password of the Netconf server, to be set.
     */
    public void setPassword(String password) throws NetconfException {
        if (isConnected()) {
            throw new NetconfException("Can't change password on a live device."
                    + "Close the device first.");
        }
        this.password = password;
    }

    /**
     * Set path of the RSA/DSA private key.
     *
     * @param pemKeyFile Path of the file containing RSA/DSA private key.
     */
    public void setPemKeyFile(String pemKeyFile) throws NetconfException {
        if (isConnected()) {
            throw new NetconfException("Can't change private key on a live " +
                    "device.Close the device first.");
        }
        this.pemKeyFile = pemKeyFile;
        keyBasedAuthentication = true;
    }

    /**
     * Set the client capabilities to be advertised to the Netconf server.
     *
     * @param capabilities Client capabilities to be advertised to the Netconf server.
     */
    public void setCapabilities(List<String> capabilities) throws NetconfException {
        if (capabilities == null) {
            throw new IllegalArgumentException("Client capabilities cannot be "
                    + "null");
        }
        if (isConnected()) {
            throw new NetconfException("Can't change client capabilities on a "
                    + "live device.Close the device first.");
        }
        helloRpc = createHelloRPC(capabilities);
    }

    /**
     * Set the port number to establish Netconf session over SSH-2.
     *
     * @param port Port number.
     */
    public void setPort(int port) throws NetconfException {
        if (isConnected()) {
            throw new NetconfException("Can't change port number on a live " +
                    "device.Close the device first.");
        }
        this.port = port;
    }

    /**
     * Get hostname of the Netconf server.
     *
     * @return Hostname of the device.
     */
    public String gethostName() {
        return this.hostName;
    }

    public NetconfSession createNetconfSession() throws NetconfException, UnknownHostException {
        return createNetconfSession(DEFAULT_TIMEOUT_MILLISECONDS);
    }


        /**
         * Create a new Netconf session.
         *
         * @return NetconfSession
         * @throws NetconfException if there are issues communicating with the Netconf server.
         */
    public NetconfSession createNetconfSession(int timeoutMilliSeconds) throws NetconfException, UnknownHostException {
        Session normalSession;
        sshClient = new SSHClient();
        sshClient.addHostKeyVerifier(new PromiscuousVerifier());
        if (!isConnected()) {
            try {
                sshClient.loadKnownHosts();
                if (timeout != 0) {
                    sshClient.setTimeout(timeoutMilliSeconds);
                }
                log.info("Connecting to host {} on port {}.", hostName, port);
                sshClient.connect(hostName, port);
                log.info("Connected to host {} - Timeout set to {}.", hostName, timeoutMilliSeconds);
            } catch (UnknownHostException e) {
              throw e;
            } catch (IOException e) {
                throw new NetconfException(e.toString());
            }
            try {
                if (keyBasedAuthentication) {
                    PKCS8KeyFile keyFile = new PKCS8KeyFile();
                    keyFile.init(pemKeyFile, null);
                    sshClient.auth(userName, new AuthPublickey(keyFile));
                } else {
                    sshClient.authPassword(userName, password);
                }

            } catch (IOException e) {
                throw new NetconfException("Authentication failed:" +
                        e.getMessage());
            }
            if (!sshClient.isAuthenticated())
                throw new NetconfException("Authentication failed.");
        }
        try {
            normalSession = sshClient.startSession();
            normalSession.startSubsystem("netconf");
            return new NetconfSession(normalSession, helloRpc, builder);
        } catch (IOException e) {
            throw new NetconfException("Failed to create Netconf session:" +
                    e.getMessage());
        }
    }

    /**
     * Reboot the device.
     *
     * @return RPC reply sent by Netconf server.
     * @throws java.io.IOException If there are issues communicating with the Netconf server.
     */
    public String reboot() throws IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.reboot();
    }

    private boolean isConnected() {
        if (sshClient == null) {
            return false;
        }
        return sshClient.isConnected();
    }

    /**
     * Close the connection to the Netconf server. All associated Netconf
     * sessions will be closed, too. Can be called at any time. Don't forget to
     * call this once you don't need the device anymore.
     *
     * @throws IOException if there is an error closing the channel.
     */
    public void close() throws IOException {
        if (!isConnected()) {
            return;
        }
        sshClient.disconnect();
    }

    /**
     * Execute a command in shell mode.
     *
     * @param command The command to be executed in shell mode.
     * @return Result of the command execution, as a String.
     * @throws IOException if there are issues communicating with the Netconf server.
     */
    public String runShellCommand(String command) throws IOException {
        if (!isConnected()) {
            return "Could not find open connection.";
        }
        Session session = sshClient.startSession();
        session.exec(command);
        InputStream stdout;
        BufferedReader bufferReader;
        stdout = session.getInputStream();

        bufferReader = new BufferedReader(new InputStreamReader(stdout, Charset.defaultCharset()));
        try {
            StringBuilder reply = new StringBuilder();
            while (true) {
                String line;
                try {
                    line = bufferReader.readLine();
                } catch (Exception e) {
                    throw new NetconfException(e.getMessage());
                }
                if (line == null || line.equals(""))
                    break;
                reply.append(line).append("\n");
            }
            return reply.toString();
        } finally {
            bufferReader.close();
        }
    }

    /**
     * Execute a command in shell mode.
     *
     * @param command The command to be executed in shell mode.
     * @return Result of the command execution, as a BufferedReader. This is
     * useful if we want continuous stream of output, rather than wait
     * for whole output till command execution completes.
     * @throws IOException if there are issues communicating with the Netconf server.
     */
    public BufferedReader runShellCommandRunning(String command)
            throws IOException {
        if (!isConnected()) {
            throw new IOException("Could not find open connection");
        }
        Session session = sshClient.startSession();
        session.exec(command);
        InputStream stdout = session.getInputStream();
        return new BufferedReader(new InputStreamReader(stdout, Charset.defaultCharset()));
    }

    /**
     * Get the client capabilities that are advertised to the Netconf server
     * by default.
     *
     * @return List of default client capabilities.
     */
    private List<String> getDefaultClientCapabilities() {
        List<String> defaultCap = new ArrayList<>();
        defaultCap.add("urn:ietf:params:xml:ns:netconf:base:1.0");
        defaultCap.add("urn:ietf:params:xml:ns:netconf:base:1.0#candidate");
        defaultCap.add("urn:ietf:params:xml:ns:netconf:base:1.0#confirmed-commit");
        defaultCap.add("urn:ietf:params:xml:ns:netconf:base:1.0#validate");
        defaultCap.add("urn:ietf:params:xml:ns:netconf:base:1.0#url?protocol=http,ftp,file");
        return defaultCap;
    }

    /**
     * Send an RPC(as String object) over the default Netconf session and get
     * the response as an XML object.
     * <p>
     *
     * @param rpcContent RPC content to be sent. For example, to send an rpc
     *                   &lt;rpc&gt;&lt;get-chassis-inventory/&gt;&lt;/rpc&gt;, the
     *                   String to be passed can be
     *                   "&lt;get-chassis-inventory/&gt;" OR
     *                   "get-chassis-inventory" OR
     *                   "&lt;rpc&gt;&lt;get-chassis-inventory/&gt;&lt;/rpc&gt;"
     * @return RPC reply sent by Netconf server
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public XML executeRPC(String rpcContent) throws SAXException, IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.executeRPC(rpcContent);
    }

    /**
     * Send an RPC(as XML object) over the Netconf session and get the response
     * as an XML object.
     * <p>
     *
     * @param rpc RPC to be sent. Use the XMLBuilder to create RPC as an
     *            XML object.
     * @return RPC reply sent by Netconf server
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public XML executeRPC(XML rpc) throws SAXException, IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.executeRPC(rpc);
    }

    /**
     * Send an RPC(as Document object) over the Netconf session and get the
     * response as an XML object.
     * <p>
     *
     * @param rpcDoc RPC content to be sent, as a org.w3c.dom.Document object.
     * @return RPC reply sent by Netconf server
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public XML executeRPC(Document rpcDoc) throws SAXException, IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.executeRPC(rpcDoc);
    }

    /**
     * Send an RPC(as String object) over the default Netconf session and get
     * the response as a BufferedReader.
     * <p>
     *
     * @param rpcContent RPC content to be sent. For example, to send an rpc
     *                   &lt;rpc&gt;&lt;get-chassis-inventory/&gt;&lt;/rpc&gt;, the
     *                   String to be passed can be
     *                   "&lt;get-chassis-inventory/&gt;" OR
     *                   "get-chassis-inventory" OR
     *                   "&lt;rpc&gt;&lt;get-chassis-inventory/&gt;&lt;/rpc&gt;"
     * @return RPC reply sent by Netconf server as a BufferedReader. This is
     * useful if we want continuous stream of output, rather than wait
     * for whole output till rpc execution completes.
     * @throws java.io.IOException if there are errors communicating with the Netconf server.
     */
    public BufferedReader executeRPCRunning(String rpcContent) throws IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.executeRPCRunning(rpcContent);
    }

    /**
     * Send an RPC(as XML object) over the Netconf session and get the response
     * as a BufferedReader.
     * <p>
     *
     * @param rpc RPC to be sent. Use the XMLBuilder to create RPC as an
     *            XML object.
     * @return RPC reply sent by Netconf server as a BufferedReader. This is
     * useful if we want continuous stream of output, rather than wait
     * for whole output till command execution completes.
     * @throws java.io.IOException if there are errors communicating with the Netconf server.
     */
    public BufferedReader executeRPCRunning(XML rpc) throws IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.executeRPCRunning(rpc);
    }

    /**
     * Send an RPC(as Document object) over the Netconf session and get the
     * response as a BufferedReader.
     * <p>
     *
     * @param rpcDoc RPC content to be sent, as a org.w3c.dom.Document object.
     * @return RPC reply sent by Netconf server as a BufferedReader. This is
     * useful if we want continuous stream of output, rather than wait
     * for whole output till command execution completes.
     * @throws java.io.IOException If there are errors communicating with the Netconf server.
     */
    public BufferedReader executeRPCRunning(Document rpcDoc) throws IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.executeRPCRunning(rpcDoc);
    }

    /**
     * Get the session ID of the Netconf session.
     *
     * @return Session ID
     */
    public String getSessionId() {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot get session ID, you need " +
                    "to establish a connection first.");
        }
        return this.defaultSession.getSessionId();
    }

    /**
     * Check if the last RPC reply returned from Netconf server has any error.
     *
     * @return true if any errors are found in last RPC reply.
     */
    public boolean hasError() throws SAXException, IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("No RPC executed yet, you need to" +
                    " establish a connection first.");
        }
        return this.defaultSession.hasError();
    }

    /**
     * Check if the last RPC reply returned from Netconf server has any warning.
     *
     * @return true if any errors are found in last RPC reply.
     */
    public boolean hasWarning() throws SAXException, IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("No RPC executed yet, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.hasWarning();
    }

    /**
     * Check if the last RPC reply returned from Netconf server, contains
     * &lt;ok/&gt; tag.
     *
     * @return true if &lt;ok/&gt; tag is found in last RPC reply.
     */
    public boolean isOK() {
        if (defaultSession == null) {
            throw new IllegalStateException("No RPC executed yet, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.isOK();
    }

    /**
     * Locks the candidate configuration.
     *
     * @return true if successful.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public boolean lockConfig() throws IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.lockConfig();
    }

    /**
     * Unlocks the candidate configuration.
     *
     * @return true if successful.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public boolean unlockConfig() throws IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.unlockConfig();
    }

    /**
     * Loads the candidate configuration, Configuration should be in XML format.
     *
     * @param configuration Configuration,in XML format, to be loaded. For example,
     *                      "&lt;configuration&gt;&lt;system&gt;&lt;services&gt;&lt;ftp/&gt;
     *                      &lt;services/&gt;&lt;/system&gt;&lt;/configuration/&gt;"
     *                      will load 'ftp' under the 'systems services' hierarchy.
     * @param loadType      You can choose "merge" or "replace" as the loadType.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void loadXMLConfiguration(String configuration, String loadType)
            throws IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.loadXMLConfiguration(configuration, loadType);
    }

    /**
     * Loads the candidate configuration, Configuration should be in text/tree
     * format.
     *
     * @param configuration Configuration,in text/tree format, to be loaded. For example,
     *                      " system {
     *                      services {
     *                      ftp;
     *                      }
     *                      }"
     *                      will load 'ftp' under the 'systems services' hierarchy.
     * @param loadType      You can choose "merge" or "replace" as the loadType.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void loadTextConfiguration(String configuration, String loadType)
            throws IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.loadTextConfiguration(configuration, loadType);
    }

    /**
     * Loads the candidate configuration, Configuration should be in set
     * format.
     * NOTE: This method is applicable only for JUNOS release 11.4 and above.
     *
     * @param configuration Configuration,in set format, to be loaded. For example,
     *                      "set system services ftp"
     *                      will load 'ftp' under the 'systems services' hierarchy.
     *                      To load multiple set statements, separate them by '\n' character.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void loadSetConfiguration(String configuration) throws
            IOException,
            SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.loadSetConfiguration(configuration);
    }

    /**
     * Loads the candidate configuration from file,
     * configuration should be in XML format.
     *
     * @param configFile Path name of file containing configuration,in xml format,
     *                   to be loaded.
     * @param loadType   You can choose "merge" or "replace" as the loadType.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void loadXMLFile(String configFile, String loadType)
            throws IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.loadXMLFile(configFile, loadType);
    }

    /**
     * Loads the candidate configuration from file,
     * configuration should be in text/tree format.
     *
     * @param configFile Path name of file containing configuration,in xml format,
     *                   to be loaded.
     * @param loadType   You can choose "merge" or "replace" as the loadType.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void loadTextFile(String configFile, String loadType)
            throws IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.loadTextFile(configFile, loadType);
    }

    /**
     * Loads the candidate configuration from file,
     * configuration should be in set format.
     * NOTE: This method is applicable only for JUNOS release 11.4 and above.
     *
     * @param configFile Path name of file containing configuration,in set format,
     *                   to be loaded.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void loadSetFile(String configFile) throws
            IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.loadSetFile(configFile);
    }

    /**
     * Commit the candidate configuration.
     *
     * @throws net.juniper.netconf.CommitException if there was an error committing the configuration.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void commit() throws CommitException, IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.commit();
    }

    /**
     * Commit the candidate configuration, temporarily. This is equivalent of
     * 'commit confirm'
     *
     * @param seconds Time in seconds, after which the previous active configuration
     *                is reverted back to.
     * @throws net.juniper.netconf.CommitException if there was an error committing the configuration.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void commitConfirm(long seconds) throws CommitException, IOException,
            SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.commitConfirm(seconds);
    }

    /**
     * Commit full is an unsupported Juniper command that will commit the config and then signal all processes to
     * check the configuration for changes. A normal commit only signals processes where there data has been modified.
     *
     * @throws CommitException if there is an error commiting the config.
     * @throws IOException if there is an error communicating with the Netconf server.
     * @throws SAXException if there is an error parsing the XML Netconf response.
     */
    public void commitFull() throws CommitException, IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.commitFull();
    }

    /**
     * Loads and commits the candidate configuration, Configuration can be in
     * text/xml format.
     *
     * @param configFile Path name of file containing configuration,in text/xml format,
     *                   to be loaded. For example,
     *                   " system {
     *                   services {
     *                   ftp;
     *                   }
     *                   }"
     *                   will load 'ftp' under the 'systems services' hierarchy.
     *                   OR
     *                   "&lt;configuration&gt;&lt;system&gt;&lt;services&gt;&lt;ftp/&gt;&lt;
     *                   services/&gt;&lt;/system&gt;&lt;/configuration/&gt;"
     *                   will load 'ftp' under the 'systems services' hierarchy.
     * @param loadType   You can choose "merge" or "replace" as the loadType.
     * @throws net.juniper.netconf.CommitException if there was an error committing the configuration.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public void commitThisConfiguration(String configFile, String loadType)
            throws CommitException, IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        this.defaultSession.commitThisConfiguration(configFile, loadType);
    }

    /**
     * Retrieve the candidate configuration, or part of the configuration.
     *
     * @param configTree configuration hierarchy to be retrieved as the argument.
     *                   For example, to get the whole configuration, argument should be
     *                   &lt;configuration&gt;&lt;/configuration&gt;
     * @return configuration data as XML object.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public XML getCandidateConfig(String configTree) throws SAXException,
            IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.getCandidateConfig(configTree);
    }

    /**
     * Retrieve the running configuration, or part of the configuration.
     *
     * @param configTree configuration hierarchy to be retrieved as the argument.
     *                   For example, to get the whole configuration, argument should be
     *                   &lt;configuration&gt;&lt;/configuration&gt;
     * @return configuration data as XML object.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public XML getRunningConfig(String configTree) throws SAXException,
            IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.getRunningConfig(configTree);
    }

    /**
     * Retrieve the whole candidate configuration.
     *
     * @return configuration data as XML object.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public XML getCandidateConfig() throws SAXException, IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.getCandidateConfig();
    }

    /**
     * Retrieve the whole running configuration.
     *
     * @return configuration data as XML object.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public XML getRunningConfig() throws SAXException, IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.getRunningConfig();
    }

    /**
     * Validate the candidate configuration.
     *
     * @return true if validation successful.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public boolean validate() throws IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.validate();
    }

    /**
     * Run a cli command, and get the corresponding output.
     * NOTE: The text output is supported for JUNOS 11.4 and later.
     *
     * @param command the cli command to be executed.
     * @return result of the command.
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     * @throws org.xml.sax.SAXException If there are errors parsing the XML reply.
     */
    public String runCliCommand(String command) throws IOException, SAXException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.runCliCommand(command);
    }

    /**
     * Run a cli command.
     *
     * @param command the cli command to be executed.
     * @return result of the command, as a BufferedReader. This is
     * useful if we want continuous stream of output, rather than wait
     * for whole output till command execution completes.
     * @throws java.io.IOException If there are errors communicating with the Netconf server.
     */
    public BufferedReader runCliCommandRunning(String command) throws IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        return this.defaultSession.runCliCommandRunning(command);
    }

    /**
     * This method should be called for load operations to happen in 'private'
     * mode.
     *
     * @param mode Mode in which to open the configuration.
     *             Permissible mode(s): "private"
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     */
    public void openConfiguration(String mode) throws IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        defaultSession.openConfiguration(mode);
    }

    /**
     * This method should be called to close a private session, in case its
     * started.
     *
     * @throws java.io.IOException If there are errors communicating with the netconf server.
     */
    public void closeConfiguration() throws IOException {
        if (defaultSession == null) {
            throw new IllegalStateException("Cannot execute RPC, you need to " +
                    "establish a connection first.");
        }
        defaultSession.closeConfiguration();
    }

    /**
     * Returns the last RPC reply sent by Netconf server.
     *
     * @return Last RPC reply, as a string
     */
    public String getLastRPCReply() {
        return this.defaultSession.getLastRPCReply();
    }

}

