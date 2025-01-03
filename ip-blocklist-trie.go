package rdns

import "net"

// Datastructure for efficient search of a list of CIDR addresses to see if
// an IP is contained in one of the CIDR ranges in the list. While it uses
// ideas from routing table implementations as described in
// https://vincent.bernat.ch/en/blog/2017-ipv4-route-lookup-linux, it differs
// in that it looks for the shortest prefix (biggest network match) since
// it's sufficient to know if an IP is covered by one of the networks
type ipBlocklistTrie struct {
	root *ipBlocklistNode
}

type ipBlocklistNode struct {
	left, right *ipBlocklistNode
	leaf        bool
}

func (t *ipBlocklistTrie) remove(n *net.IPNet) {
    t.root = t.removeNode(t.root, n.IP, 0, len(n.IP)*8, 0)
}

func (t *ipBlocklistTrie) removeNode(node *ipBlocklistNode, ip net.IP, bitIndex, size, level int) *ipBlocklistNode {
    if node == nil {
        return nil
    }

    if bitIndex == size {
        // Check if this node is a leaf for the network
        if node.leaf {
            node.leaf = false
            // If it's a leaf, and no children, we can remove this node
            if node.left == nil && node.right == nil {
                return nil
            }
        }
        return node
    }

    // Finding the bit at bitIndex in the IP
    b := bit(ip, bitIndex)

    // Go to the appropriate child based on the bit
    if b == 1 {
        node.right = t.removeNode(node.right, ip, bitIndex+1, size, level+1)
    } else {
        node.left = t.removeNode(node.left, ip, bitIndex+1, size, level+1)
    }

    // If this node is a leaf node and has no children, it can be removed
    if node.leaf && node.left == nil && node.right == nil {
        return nil
    }

    return node
}

// Add a network to the trie with an identifier.
func (t *ipBlocklistTrie) add(n *net.IPNet) {
	if t.root == nil {
		t.root = new(ipBlocklistNode)
	}
	prefix, _ := n.Mask.Size()
	p := t.root
	for i := 0; i < prefix; i++ {
		if p.leaf { // stop if we already have a shorter prefix than this
			break
		}
		b := bit(n.IP, i)
		if b == 1 {
			if p.right == nil {
				p.right = new(ipBlocklistNode)
			}
			p = p.right
		} else {
			if p.left == nil {
				p.left = new(ipBlocklistNode)
			}
			p = p.left
		}
	}

	// Mark this as the leaf-node. We care about the shortest prefix
	// so nothing should go past this when building the trie
	p.left = nil
	p.right = nil
	p.leaf = true
}

// Returns true, the string representation of the network covering the IP, and the identifier.
func (t *ipBlocklistTrie) hasIP(ip net.IP) (string, bool) {
	if t.root == nil {
		return "", false
	}
	p := t.root
	size := 32
	if addr := ip.To4(); addr == nil {
		size = 128
	} else {
		ip = addr // make sure we use the 4-byte representation of an IPv4
	}
	for i := 0; i < size; i++ {
		if p.leaf {
			return ruleString(ip, i), true // برگرداندن شناسه در صورت وجود IP
		}
		b := bit(ip, i)
		if b == 1 {
			if p.right == nil {
				return "", false
			}
			p = p.right
		} else {
			if p.left == nil {
				return "", false
			}
			p = p.left
		}
	}
	// Todo Kontorol
	return ruleString(ip, size), true
}



// // Add a network to the trie.
// func (t *ipBlocklistTrie) add(n *net.IPNet) {
// 	if t.root == nil {
// 		t.root = new(ipBlocklistNode)
// 	}
// 	prefix, _ := n.Mask.Size()
// 	p := t.root
// 	for i := 0; i < prefix; i++ {
// 		if p.leaf { // stop if we already have a shorter prefix than this
// 			break
// 		}
// 		b := bit(n.IP, i)
// 		if b == 1 {
// 			if p.right == nil {
// 				p.right = new(ipBlocklistNode)
// 			}
// 			p = p.right
// 		} else {
// 			if p.left == nil {
// 				p.left = new(ipBlocklistNode)
// 			}
// 			p = p.left
// 		}
// 	}

// 	// Mark this as the leaf-node. We care about the shortest prefix
// 	// so nothing should go past this when building the trie
// 	p.left = nil
// 	p.right = nil
// 	p.leaf = true
// }

// // Returns true and the string representation of the network covering
// // the IP.
// func (t *ipBlocklistTrie) hasIP(ip net.IP) (string, bool) {
// 	if t.root == nil {
// 		return "", false
// 	}
// 	p := t.root
// 	size := 32
// 	if addr := ip.To4(); addr == nil {
// 		size = 128
// 	} else {
// 		ip = addr // make sure we use the 4-byte representation of an IPv4
// 	}
// 	for i := 0; i < size; i++ {
// 		if p.leaf {
// 			return ruleString(ip, i), true
// 		}
// 		b := bit(ip, i)
// 		if b == 1 {
// 			if p.right == nil {
// 				return "", false
// 			}
// 			p = p.right
// 		} else {
// 			if p.left == nil {
// 				return "", false
// 			}
// 			p = p.left
// 		}
// 	}
// 	return ruleString(ip, size), true
// }

func ruleString(ip net.IP, maskBits int) string {
	size := 32
	if addr := ip.To4(); addr == nil {
		size = 128
	}
	mask := net.CIDRMask(maskBits, size)
	ipNet := &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}
	return ipNet.String()
}

var bitMask = []byte{
	128,
	64,
	32,
	16,
	8,
	4,
	2,
	1,
}

// Returns n'th bit from an IP address from the left.
func bit(ip net.IP, n int) int {
	byteIndex := n / 8
	bitIndex := n % 8
	if (ip[byteIndex] & bitMask[bitIndex]) == 0 {
		return 0
	}
	return 1
}
