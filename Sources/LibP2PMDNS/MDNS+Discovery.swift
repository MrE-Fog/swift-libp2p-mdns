//
//  MDNS+Discovery.swift
//  
//
//  Created by Brandon Toms on 4/6/22.
//

import LibP2P

/// Discovery Conformance
extension MulticastPeerDiscovery {
    public func advertise(service protocol: String, options:Options? = nil) -> EventLoopFuture<TimeAmount> {
        self.registerService(name: `protocol`).transform(to: .seconds(120))
    }
    
    public func findPeers(supportingService protocol: String, options:Options? = nil) -> EventLoopFuture<DiscoverdPeers> {
        self.queryForService(`protocol`).map { socketAddress in
            return socketAddress.compactMap { try? $0.toMultiaddr() }.compactMap {
                guard let cid = $0.getPeerID(), let pid = try? PeerID(cid: cid) else { return nil }
                return PeerInfo(peer: pid, addresses: [$0])
            }
        }.map { peers in
            return DiscoverdPeers(peers: peers, cookie: nil)
        }
    }
}
