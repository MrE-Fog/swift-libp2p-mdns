import XCTest
@testable import LibP2PMDNS
import NIO
import DNS
import Network
import Multiaddr
import PeerID

final class LibP2PMDNSTests: XCTestCase {
    //static let ourIPAddress = "192.168.1.21"
    let ourIPAddress = try! System.enumerateDevices().first(where: { device in
        guard device.name == "en0" && device.address != nil else { return false }
        guard let ma = try? device.address?.toMultiaddr().tcpAddress else { return false }
        
        return ma.ip4
    }).map { try! $0.address!.toMultiaddr().tcpAddress!.address }!
    
    /// System.enumerateDevices
    func testSystemDevices() throws {
        for device in try! System.enumerateDevices() {
            print("Description: \(device)")
            print("Interface Index: \(device.interfaceIndex)")
            print("Name: \(device.name)")
            print("Address: \(String(describing: device.address))")
            print("Broadcast Address: \(String(describing: device.broadcastAddress))")
            print("Netmask: \(String(describing: device.netmask))")
        }
    }
    
    func testSystemDevicesEN0() throws {
        try System.enumerateDevices().filter({ device in
            guard device.name == "en0" && device.address != nil else { return false }
            guard let ma = try? device.address?.toMultiaddr().tcpAddress else { return false }
            
            return ma.ip4
            
        }).forEach { device in
            print("Description: \(device)")
            print("Interface Index: \(device.interfaceIndex)")
            print("Name: \(device.name)")
            print("Address: \(try! device.address!.toMultiaddr().tcpAddress!.address)")
            print("Broadcast Address: \(String(describing: device.broadcastAddress))")
            print("Netmask: \(String(describing: device.netmask))")
        }
    }
    
    func testFixSameHostAddresses() {
        let hostIP4 = "192.168.1.21"
        let hostIP6 = "f4:d4:88:5c:bf:7b"
        let mas = [
            try! Multiaddr("/ip4/192.168.1.21/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV"),
            try! Multiaddr("/ip4/127.0.0.1/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV"),
            try! Multiaddr("/ip4/192.168.1.23/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV"),
            //try! Multiaddr("/ip6/f4:d4:88:5c:bf:7b/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV"),
            //try! Multiaddr("/ip6/b4:44:28:5d:af:7c/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV")
        ]
        
        let fixed = mas.compactMap { ma -> Multiaddr? in
            guard let addy = ma.addresses.first else { return nil }
            switch addy.codec {
            case .ip4:
                if addy.addr == hostIP4 {
                    do {
                        var new = try Multiaddr(.ip4, address: "127.0.0.1")
                        try ma.addresses.dropFirst().forEach {
                            new = try new.encapsulate(proto: $0.codec, address: $0.addr)
                        }
                        return new
                    } catch {
                        return nil
                    }
                } else {
                    return ma
                }
            case .ip6:
                if addy.addr == hostIP6 {
                    do {
                        var new = try Multiaddr(.ip6, address: "::1")
                        try ma.addresses.dropFirst().forEach {
                            new = try new.encapsulate(proto: $0.codec, address: $0.addr)
                        }
                        return new
                    } catch {
                        return nil
                    }
                } else {
                    return ma
                }
            default:
                return nil
            }
        }
        
        print(fixed)
    }
    
    func testFixSameHostAddresses2() {
        let hostIP4 = "192.168.1.21"
        let hostIP6 = "f4:d4:88:5c:bf:7b"
        let mas = [
            try! Multiaddr("/ip4/192.168.1.21/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV"),
            try! Multiaddr("/ip4/127.0.0.1/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV"),
            try! Multiaddr("/ip4/192.168.1.23/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV"),
            //try! Multiaddr("/ip6/f4:d4:88:5c:bf:7b/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV"),
            //try! Multiaddr("/ip6/b4:44:28:5d:af:7c/tcp/1234/p2p/QmX99Bk1CoBc787KY36tcy43AbXoo1HiG1WTDpenmJecNV")
        ]
        
        let fixed = mas.compactMap { ma -> Multiaddr? in
            guard let addy = ma.addresses.first else { return nil }
            switch addy.codec {
            case .ip4:
                return ma.replace(address: hostIP4, with: "127.0.0.1", forCodec: .ip4)
            case .ip6:
                return ma.replace(address: hostIP6, with: "::1", forCodec: .ip6)
            default:
                return nil
            }
        }
        
        print(fixed)
    }
    
    /// This is an example of how we can register a service using the dnssd library / daemon
    /// We register a `_http._tcp` service with the name "MyTest" on port 3338 for 10 seconds and then unregsiter the service by safely deallocating the `DNSServiceRef`
    /// Eventually it would be nice to not have to rely on dnssd, and instead register services through SwiftNIO udp multicast directly, but I haven't figured out how to do that yet.
    func testRegisterService() throws {
        /// Attempt to register a custom service
        var dnsService:DNSServiceRef? = nil
        let flags:DNSServiceFlags = DNSServiceFlags()
        DNSServiceRegister(&dnsService, flags, 0, "chat-room-name", "_p2p._udp", "", "", 3338, 0, "", nil, nil)
        
        let exp = expectation(description: "10 second delay")
        
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(10)) {
            exp.fulfill()
        }
        
        waitForExpectations(timeout: 15, handler: nil)
        
        DNSServiceRefDeallocate(dnsService)
    }
    
    func testCreateTextRecord() throws {
        let txtRecord = DNS.TextRecord(name: "chat-room-name", ttl: 3600, attributes: ["port":"3338", "test":"something"])
        var txtBytes = Data()
        var labels = Labels()
        try txtRecord.serialize(onto: &txtBytes, labels: &labels)
    
        print(UInt16(txtBytes.count).bytes)
        print(txtBytes.asString(base: .base16))
    }
    
    func testCreateTextRecord2() throws {
        var txtRecord = TXTRecordRef()
        var buffer = Data()
        TXTRecordCreate(&txtRecord, 1, &buffer)
        var value = "1234"
        TXTRecordSetValue(&txtRecord, "test", UInt8(value.bytes.count), &value)
    
        print(txtRecord)
        print(TXTRecordGetLength(&txtRecord))
        
        TXTRecordDeallocate(&txtRecord)
    }
    
    /// This doesn't work. I was hoping to be able to listen in / get a copy of all the udp packets destined for the mdns endpoint, but we cant bind to / listen to port 5353 because it's already in use...
    func testUDP_mDNS_Listener() throws {
        let listener:NWListener = try NWListener(using: .udp, on: 5353)
        
        listener.stateUpdateHandler = { (newState) in
            switch newState {
            case .ready:
                print("ready")
            default:
                print("\(newState)")
                break
            }
        }
        
        listener.newConnectionHandler = { (newConnection) in
            newConnection.stateUpdateHandler = {newState in
                switch newState {
                case .ready:
                    print("ready")
                default:
                    break
                }
            }
            newConnection.start(queue: DispatchQueue(label: "newconn"))
            
            newConnection.receiveMessage { (data, context, isComplete, error) in
                // Decode and continue processing data
                print("Received Message")
                
                if let d = data, let repsonse = try? DNS.Message(deserialize: d) {
                    print(repsonse)
                } else {
                    print("Failed to decode DNS Message Response")
                }
                
            }
        }
        
        listener.start(queue: .main)
        
        let exp = expectation(description: "Timeout")
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(10)) {
            exp.fulfill()
        }

        waitForExpectations(timeout: 15, handler: nil)
        
        listener.cancel()
    }
    
    /// This test registers a mDNS Service using our PeerID.b58String as our service/instance name, under the _p2p._udp.local domain. It also includes a TextRecord which includes a key:value dictionary of the libp2p instance's listening addresses (example "tcp":1234, "udp":12345, "ws":1235, etc...)
    ///
    /// We can then query the mDNS multicast group at 224.0.0.251 for services under the `_p2p._udp.local` domain and find all of the libp2p instances on our local network.
    /// - Their peerID is the instance name (so we can verify that who we dialed is in fact who they say they are)
    /// - Their ip address is available via the HostRecords (both ipv4 and ipv6)
    /// - Their listening addresses/ports are available in the TxtRecord under the `attributes` key:value dictionary
    ///
    /// An example response from a _p2p._udp service query
    /// ```
    /// DNS Response(id: 0, returnCode: 0, authoritativeAnswer: true, truncation: false, recursionDesired: false, recursionAvailable: false, questions: [DNS.Question(name: "_p2p._udp.local.", type: *, unique: false, internetClass: A)], answers: [DNS.PointerRecord(name: "_p2p._udp.local.", unique: false, internetClass: A, ttl: 10, destination: "QmTbC9GvKDoMfguPK8rxUbZTeAy66RFEb4BxgV4enR4yuX._p2p._udp.local.")], authorities: [], additional: [DNS.ServiceRecord(name: "QmTbC9GvKDoMfguPK8rxUbZTeAy66RFEb4BxgV4enR4yuX._p2p._udp.local.", unique: false, internetClass: A, ttl: 10, priority: Unknown, weight: Unknown, port: Unknown, server: "..."), DNS.TextRecord(name: "QmTbC9GvKDoMfguPK8rxUbZTeAy66RFEb4BxgV4enR4yuX._p2p._udp.local.", unique: false, internetClass: A, ttl: 10, attributes: ["tcp": "1234", "udp": "23452"], values: [])])
    /// ```
    func testRegisterServiceAndQueryForIt() throws {
        let peerID = try PeerID(.Ed25519)
        
        /// Create our libp2p multicast udp server
        let chatMulticastGroup = try! SocketAddress(ipAddress: "224.0.0.251", port: 5353)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let datagramChannel = try LibP2PMDNSTests.makeUDPMulticastHost(group, interfaceAddress: ourIPAddress, onMulticastGroup: chatMulticastGroup)
        
        /// Attempt to register a custom service
        var dnsService:DNSServiceRef? = nil
        let flags:DNSServiceFlags = DNSServiceFlags()
        
        /// An example of a simple service with an empty text record
        //DNSServiceRegister(&dnsService, flags, 0, "chat-room-name", "_p2p._udp", "", "", 3338, 1, nil, nil, nil)
        
        /// An example of a service that contains a text record with custom key:value pairs
        /// Create a TxtRecord and append any necessary data (aka our listening addresses, including port and peerid...)
        var txtRecord = TXTRecordRef()
        var buffer = Data()
        TXTRecordCreate(&txtRecord, 1, &buffer)
        var tcpPort = "1234"
        var udpPort = "23452"
        TXTRecordSetValue(&txtRecord, "tcp", UInt8(tcpPort.bytes.count), &tcpPort)
        TXTRecordSetValue(&txtRecord, "udp", UInt8(udpPort.bytes.count), &udpPort)
        DNSServiceRegister(&dnsService, flags, 0, peerID.b58String, "_p2p._udp", "", "", 3338, TXTRecordGetLength(&txtRecord), TXTRecordGetBytesPtr(&txtRecord), nil, nil)
        
        
        /// Trying to create a TextRecord using the DNS message library, serialize it and include it in the dns-sd register service method... This doesn't work!
//        let txtRecord = DNS.TextRecord(name: "chat-room-name", ttl: 3600, attributes: ["port":"3338", "test":"something"])
//        var txtBytes = Data()
//        var labels = Labels()
//        try txtRecord.serialize(onto: &txtBytes, labels: &labels)
//        DNSServiceRegister(&dnsService, flags, 0, "chat-room-name", "_p2p._udp", "", "", 3338, UInt16(txtBytes.count), &txtBytes, nil, nil)
        
        
        print("Registered Service")
        
        let exp = expectation(description: "Performing Query")
        group.next().scheduleTask(in: .seconds(2)) {
            /// Lets send something
            print("Sending Data")
            
            let question = Question(name: "_p2p._udp.local", type: .all) //This works!!
            
            let query = Message(
                type: .query,
                questions: [question]
            )

            datagramChannel.writeAndFlush(AddressedEnvelope(remoteAddress: chatMulticastGroup, data: try! query.serialize()), promise: nil)

            group.next().scheduleTask(in: .seconds(10)) {
                print("Fulfilling Write Expectation")
                exp.fulfill()
            }
        }
        waitForExpectations(timeout: 15, handler: nil)
        
        print("Releasing DNS Service")
        DNSServiceRefDeallocate(dnsService)
        
        /// Close the channel and shutdown the event loop group
        print("Shutting down libp2p")
        try! datagramChannel.close().wait()
        try! group.syncShutdownGracefully()
    }
    
    static var allTests = [
        ("testSystemDevices", testSystemDevices),
        ("testRegisterService", testRegisterService),
        ("testCreateTextRecord", testCreateTextRecord),
        ("testCreateTextRecord2", testCreateTextRecord2),
        ("testUDP_mDNS_Listener", testUDP_mDNS_Listener),
        //("testUDP_Multicast_Address_Resolution", testUDP_Multicast_Address_Resolution),
        //("testUDP_Multicast_Serivce_Query", testUDP_Multicast_Serivce_Query),
        ("testRegisterServiceAndQueryForIt", testRegisterServiceAndQueryForIt)
    ]
    
}



extension LibP2PMDNSTests {
    /// A function that instantiates a new UDP Multicast Datagram Bootstrap Server/Listener that joins the mDNS multicast group at 244.0.0.251:5353
    internal static func makeUDPMulticastHost(_ group:EventLoopGroup, interfaceAddress:String, onMulticastGroup:SocketAddress) throws -> Channel {
        // We allow users to specify the interface they want to use here.
        var targetDevice: NIONetworkDevice? = nil
        if let targetAddress = try? SocketAddress(ipAddress: interfaceAddress, port: 0) {
            for device in try! System.enumerateDevices() {
                if device.address == targetAddress {
                    targetDevice = device
                    break
                }
            }

            if targetDevice == nil {
                fatalError("Could not find device for \(interfaceAddress)")
            } else {
                print("Using device: \(targetDevice!)")
            }
        }

        // Begin by setting up the basics of the bootstrap.
        let datagramBootstrap = DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                print("UDP Channel Initializer Called")
                print("Local Addres: \(channel.localAddress?.description ?? "nil")")
                return channel.pipeline.addHandler(MessageEncoder()).flatMap {
                        channel.pipeline.addHandler(MessageDecoder())
                    }
            }

            // We cast our channel to MulticastChannel to obtain the multicast operations.
        let datagramChannel = try datagramBootstrap
            .bind(host: "0.0.0.0", port: 7655)
            .flatMap { channel -> EventLoopFuture<Channel> in
                let channel = channel as! MulticastChannel
                return channel.joinGroup(onMulticastGroup, device: targetDevice).map { channel }
            }.flatMap { channel -> EventLoopFuture<Channel> in
                guard let targetDevice = targetDevice else {
                    return channel.eventLoop.makeSucceededFuture(channel)
                }
                
                let provider = channel as! SocketOptionProvider
                
                switch targetDevice.address {
                case .some(.v4(let addr)):
                    print("Setting Provider v4 \(addr.address.sin_addr)")
                    return provider.setIPMulticastIF(addr.address.sin_addr).map { channel }
                case .some(.v6):
                    print("Setting Provider v6 \(targetDevice.interfaceIndex)")
                    return provider.setIPv6MulticastIF(CUnsignedInt(targetDevice.interfaceIndex)).map { channel }
                case .some(.unixDomainSocket):
                    preconditionFailure("Should not be possible to create a multicast socket on a unix domain socket")
                case .none:
                    preconditionFailure("Should not be possible to create a multicast socket on an interface without an address")
                }
            }.wait()
        
        return datagramChannel
    }
    
    private final class MessageDecoder: ChannelInboundHandler {
        public typealias InboundIn = AddressedEnvelope<ByteBuffer>

        public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let envelope = self.unwrapInboundIn(data)
            let buffer = envelope.data
            
            //print(envelope)
            //print(Data(buffer.readableBytesView).asString(base: .base16))
            
            if let response = try? Message(deserialize: Data(buffer.readableBytesView)) {
                print(response)
                
                print(self.extractMultiaddressFromAdditionalRecords(response.additional))
                
            } else {
                print("Failed to decode DNS Message Response")
            }
        }
        
        private func extractMultiaddressFromAdditionalRecords(_ records:[ResourceRecord]) -> [Multiaddr] {
            guard records.count >= 3 else { return [] }
            
            var multiaddresses:[Multiaddr] = []
            
            /// Lets try and recover the Multiaddr
            var peerID:String? = nil
            var ip4Address:String? = nil
            var ip6Address:String? = nil
            var protos:[String:Int] = [:]
            for record in records {
                if let serRec = record as? DNS.ServiceRecord {
                    if let pid = serRec.name.split(separator: ".").first {
                        peerID = String(pid)
                    }
                }
                if let txtRec = record as? DNS.TextRecord {
                    protos = txtRec.attributes.compactMapValues({ Int($0) })
                }
                if let ipv4Rec = record as? DNS.HostRecord<DNS.IPv4> {
                    ip4Address = ipv4Rec.ip.presentation
                }
                if let ipv6Rec = record as? DNS.HostRecord<DNS.IPv6> {
                    ip6Address = ipv6Rec.ip.presentation
                }
            }
            
            if peerID != nil && !protos.isEmpty {
                /// /ip4/127.0.0.1/tcp/10000/p2p/QmQpiLteAfLv9VQHBJ4qaGNA9bVAFPBEtZDpmv4XeRtGh2
                for proto in protos {
                    if let ip4 = ip4Address, let ma = try? Multiaddr("/ip4/\(ip4)/\(proto.key)/\(proto.value)/p2p/\(peerID!)") {
                        multiaddresses.append(ma)
                    }
                    if let ip6 = ip6Address, let ma = try? Multiaddr("/ip6/\(ip6)/\(proto.key)/\(proto.value)/p2p/\(peerID!)") {
                        multiaddresses.append(ma)
                    }
                }
            }
            
            if let pidString = multiaddresses.first?.getPeerID(), let pID = try? PeerID(cid: pidString) {
                print(pID)
            } else {
                print("Failed to reconstruct PeerID from multiaddr")
            }
            
            return multiaddresses
        }
    }
    
    private final class MessageEncoder: ChannelOutboundHandler {
        public typealias OutboundIn = AddressedEnvelope<Data>
        public typealias OutboundOut = AddressedEnvelope<ByteBuffer>

        func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
            let message = self.unwrapOutboundIn(data)
            let buffer = context.channel.allocator.buffer(bytes: message.data)
            context.write(self.wrapOutboundOut(AddressedEnvelope(remoteAddress: message.remoteAddress, data: buffer)), promise: promise)
        }
    }
}

