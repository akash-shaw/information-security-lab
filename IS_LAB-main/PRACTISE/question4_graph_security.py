"""
Question 4: Graph-based Security Algorithm
Implementation of graph algorithms commonly used in network security,
access control, and cryptographic applications
"""

import random
from collections import defaultdict, deque

class GraphSecurity:
    def __init__(self):
        self.graph = defaultdict(list)
        self.nodes = set()
    
    def add_edge(self, u, v, bidirectional=True):
        """Add edge to the graph"""
        self.graph[u].append(v)
        self.nodes.add(u)
        self.nodes.add(v)
        
        if bidirectional:
            self.graph[v].append(u)
    
    def display_graph(self):
        """Display the graph structure"""
        print("Graph Structure:")
        for node in sorted(self.nodes):
            neighbors = sorted(self.graph[node])
            print(f"Node {node}: {neighbors}")
    
    def bfs_shortest_path(self, start, end):
        """Find shortest path using BFS (for access control paths)"""
        if start not in self.nodes or end not in self.nodes:
            return None
        
        queue = deque([(start, [start])])
        visited = set([start])
        
        while queue:
            current, path = queue.popleft()
            
            if current == end:
                return path
            
            for neighbor in self.graph[current]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None
    
    def dfs_all_paths(self, start, end, path=None):
        """Find all paths between two nodes using DFS"""
        if path is None:
            path = [start]
        
        if start == end:
            return [path]
        
        paths = []
        for neighbor in self.graph[start]:
            if neighbor not in path:  # Avoid cycles
                new_paths = self.dfs_all_paths(neighbor, end, path + [neighbor])
                paths.extend(new_paths)
        
        return paths
    
    def detect_cycles(self):
        """Detect cycles in the graph (important for security analysis)"""
        visited = set()
        rec_stack = set()
        cycles = []
        
        def dfs_cycle(node, path):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in self.graph[node]:
                if neighbor not in visited:
                    if dfs_cycle(neighbor, path.copy()):
                        return True
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    cycles.append(cycle)
                    return True
            
            rec_stack.remove(node)
            return False
        
        for node in self.nodes:
            if node not in visited:
                dfs_cycle(node, [])
        
        return cycles
    
    def access_control_matrix(self):
        """Generate access control matrix based on graph connectivity"""
        nodes_list = sorted(list(self.nodes))
        n = len(nodes_list)
        matrix = [[0 for _ in range(n)] for _ in range(n)]
        
        node_to_index = {node: i for i, node in enumerate(nodes_list)}
        
        for node in self.graph:
            i = node_to_index[node]
            for neighbor in self.graph[node]:
                j = node_to_index[neighbor]
                matrix[i][j] = 1
        
        return matrix, nodes_list
    
    def security_vulnerability_score(self):
        """Calculate vulnerability score based on graph properties"""
        scores = {}
        
        for node in self.nodes:
            # Calculate degree centrality (number of connections)
            degree = len(self.graph[node])
            
            # Calculate reachability (how many nodes can reach this node)
            reachable_from = 0
            for other_node in self.nodes:
                if other_node != node:
                    path = self.bfs_shortest_path(other_node, node)
                    if path:
                        reachable_from += 1
            
            # Higher degree and reachability = higher vulnerability
            vulnerability = (degree * 0.6) + (reachable_from * 0.4)
            scores[node] = vulnerability
        
        return scores
    
    def find_critical_nodes(self):
        """Find nodes whose removal would disconnect the graph"""
        critical_nodes = []
        
        for node in self.nodes:
            # Create temporary graph without this node
            temp_graph = GraphSecurity()
            for u in self.nodes:
                if u != node:
                    for v in self.graph[u]:
                        if v != node:
                            temp_graph.add_edge(u, v, bidirectional=False)
            
            # Check if graph becomes disconnected
            if len(temp_graph.nodes) > 1:
                # Try to find path between any two nodes
                nodes_list = list(temp_graph.nodes)
                path = temp_graph.bfs_shortest_path(nodes_list[0], nodes_list[-1])
                if not path:
                    critical_nodes.append(node)
        
        return critical_nodes

class NetworkSecurityGraph:
    """Specialized graph for network security analysis"""
    
    def __init__(self):
        self.security_graph = GraphSecurity()
        self.node_types = {}  # 'server', 'client', 'router', 'firewall'
        self.edge_weights = {}  # Security strength of connections
    
    def add_network_node(self, node_id, node_type, security_level=1):
        """Add a network node with type and security level"""
        self.node_types[node_id] = {'type': node_type, 'security': security_level}
        self.security_graph.nodes.add(node_id)
    
    def add_secure_connection(self, node1, node2, security_strength=1):
        """Add a secure connection between nodes"""
        self.security_graph.add_edge(node1, node2)
        self.edge_weights[(node1, node2)] = security_strength
        self.edge_weights[(node2, node1)] = security_strength
    
    def analyze_attack_paths(self, attacker_node, target_node):
        """Analyze possible attack paths from attacker to target"""
        all_paths = self.security_graph.dfs_all_paths(attacker_node, target_node)
        
        path_analysis = []
        for path in all_paths:
            # Calculate path security strength
            min_security = float('inf')
            for i in range(len(path) - 1):
                edge_security = self.edge_weights.get((path[i], path[i+1]), 1)
                min_security = min(min_security, edge_security)
            
            path_analysis.append({
                'path': path,
                'security_strength': min_security,
                'length': len(path),
                'risk_level': 'HIGH' if min_security < 3 else 'MEDIUM' if min_security < 7 else 'LOW'
            })
        
        # Sort by security strength (ascending - most vulnerable first)
        path_analysis.sort(key=lambda x: x['security_strength'])
        return path_analysis

# Example usage and demonstrations
if __name__ == "__main__":
    print("Graph-based Security Algorithm Implementation")
    print("=" * 50)
    
    # Example 1: Basic Graph Security Analysis
    print("\n1. Basic Graph Security Analysis:")
    security_graph = GraphSecurity()
    
    # Create a sample network topology
    connections = [
        ('A', 'B'), ('A', 'C'), ('B', 'D'), 
        ('C', 'D'), ('D', 'E'), ('C', 'F'),
        ('E', 'F'), ('F', 'G')
    ]
    
    for u, v in connections:
        security_graph.add_edge(u, v)
    
    security_graph.display_graph()
    
    # Find shortest path (access control)
    path = security_graph.bfs_shortest_path('A', 'G')
    print(f"\nShortest path from A to G: {path}")
    
    # Find all paths
    all_paths = security_graph.dfs_all_paths('A', 'G')
    print(f"All paths from A to G: {all_paths}")
    
    # Detect cycles
    cycles = security_graph.detect_cycles()
    print(f"Detected cycles: {cycles}")
    
    # Calculate vulnerability scores
    vuln_scores = security_graph.security_vulnerability_score()
    print(f"\nVulnerability scores: {vuln_scores}")
    
    # Find critical nodes
    critical = security_graph.find_critical_nodes()
    print(f"Critical nodes: {critical}")
    
    # Generate access control matrix
    matrix, nodes = security_graph.access_control_matrix()
    print(f"\nAccess Control Matrix:")
    print(f"Nodes: {nodes}")
    for i, row in enumerate(matrix):
        print(f"{nodes[i]}: {row}")
    
    # Example 2: Network Security Analysis
    print("\n" + "="*50)
    print("2. Network Security Analysis:")
    
    network = NetworkSecurityGraph()
    
    # Add network nodes
    network.add_network_node('Router1', 'router', 8)
    network.add_network_node('Server1', 'server', 9)
    network.add_network_node('Client1', 'client', 5)
    network.add_network_node('Firewall1', 'firewall', 10)
    network.add_network_node('DMZ', 'server', 6)
    network.add_network_node('Attacker', 'external', 1)
    
    # Add secure connections with different security strengths
    network.add_secure_connection('Attacker', 'Router1', 2)  # Weak
    network.add_secure_connection('Router1', 'Firewall1', 8)  # Strong
    network.add_secure_connection('Firewall1', 'DMZ', 7)
    network.add_secure_connection('Firewall1', 'Server1', 9)  # Very strong
    network.add_secure_connection('Router1', 'Client1', 4)  # Moderate
    network.add_secure_connection('DMZ', 'Server1', 5)
    
    # Analyze attack paths
    attack_analysis = network.analyze_attack_paths('Attacker', 'Server1')
    
    print("Attack Path Analysis:")
    for i, analysis in enumerate(attack_analysis, 1):
        print(f"Path {i}: {' -> '.join(analysis['path'])}")
        print(f"  Security Strength: {analysis['security_strength']}")
        print(f"  Risk Level: {analysis['risk_level']}")
        print(f"  Path Length: {analysis['length']}")
        print()
    
    print("Security Recommendations:")
    if attack_analysis:
        most_vulnerable = attack_analysis[0]
        print(f"- Most vulnerable path: {' -> '.join(most_vulnerable['path'])}")
        print(f"- Risk level: {most_vulnerable['risk_level']}")
        print("- Consider strengthening security on this path")
        
        if most_vulnerable['security_strength'] < 5:
            print("- URGENT: Implement additional security measures")
    
    print("\n" + "="*50)
    print("Graph algorithms completed successfully!")
