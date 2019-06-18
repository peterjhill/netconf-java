netconf-java
============

Java library for NETCONF

SUPPORT
=======

This software is not officially supported by Juniper Networks, but by a team dedicated to helping customers,
partners, and the development community.  To report bug-fixes, issues, suggestions, please contact netconf-automation-hackers@juniper.net

REQUIREMENTS
============

OpenJDK>=1.6.0

Releases
========
Latest .jar file in release section contains netconf-java compiled from Java SE 8u65.
If user wants to use some other java version, then download the source code and compile it with desired version.

v1.1.0
------

* Replaced the ssh library with [sshj](https://github.com/hierynomus/sshj)
    * Adds support for new ssh crypto algorithms
    * More modern ssh implementation
* Added support for importing and building the library with maven
* Added FindBugs code testing to maven build    

SYNOPSIS
========

    import java.io.IOException;
    import javax.xml.parsers.ParserConfigurationException;
    import net.juniper.netconf.NetconfException;
    import org.xml.sax.SAXException;

    import net.juniper.netconf.XML;
    import net.juniper.netconf.Device;

    public class ShowInterfaces {
        public static void main(String args[]) throws NetconfException,
                  ParserConfigurationException, SAXException, IOException {

            //Create device
            Device device = new Device("hostname","user","password",null);
            device.connect();

            //Send RPC and receive RPC Reply as XML
            XML rpc_reply = device.executeRPC("get-interface-information");
            /* OR
             * device.executeRPC("<get-interface-information/>");
             * OR
             * device.executeRPC("<rpc><get-interface-information/></rpc>");
             */

            //Print the RPC-Reply and close the device.
            System.out.println(rpc_reply);
            device.close();
        }
    }

LICENSE
=======

(BSD 2)

Copyright © 2013, Juniper Networks

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

(1) Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

(2) Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the authors and should not be interpreted as representing official policies, either expressed or implied, of Juniper Networks.

This software includes work that was released under the following license:

Copyright (c) 2005 - 2006 Swiss Federal Institute of Technology (ETH Zurich),
  Department of Computer Science (http://www.inf.ethz.ch),
  Christian Plattner. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

a.) Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
b.) Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
c.) Neither the name of ETH Zurich nor the names of its contributors may
    be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

The Java implementations of the AES, Blowfish and 3DES ciphers have been
taken (and slightly modified) from the cryptography package released by
"The Legion Of The Bouncy Castle".

Their license states the following:

Copyright (c) 2000 - 2004 The Legion Of The Bouncy Castle
(http://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

AUTHOR
======

[Ankit Jain](http://www.linkedin.com/in/ankitj093), Juniper Networks
