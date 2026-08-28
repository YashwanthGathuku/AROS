use aros_types::{CampaignId, EpistemicState, GraphEdge, GraphKind, GraphNode, NodeId};
use petgraph::graph::DiGraph;

#[derive(Clone, Debug)]
pub struct ActiveGraph {
    pub campaign_id: CampaignId,
    inner: DiGraph<GraphNode, GraphEdge>,
}

impl ActiveGraph {
    pub fn new(campaign_id: CampaignId) -> Self {
        Self {
            campaign_id,
            inner: DiGraph::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) -> NodeId {
        let id = node.id;
        self.inner.add_node(node);
        id
    }

    pub fn add_edge(&mut self, edge: GraphEdge) {
        let from = self.find_index(edge.from);
        let to = self.find_index(edge.to);
        if let (Some(from), Some(to)) = (from, to) {
            self.inner.add_edge(from, to, edge);
        }
    }

    pub fn nodes(&self) -> Vec<GraphNode> {
        self.inner.node_weights().cloned().collect()
    }

    pub fn edges(&self) -> Vec<GraphEdge> {
        self.inner.edge_weights().cloned().collect()
    }

    fn find_index(&self, id: NodeId) -> Option<petgraph::graph::NodeIndex> {
        self.inner
            .node_indices()
            .find(|index| self.inner[*index].id == id)
    }

    pub fn node_count(&self) -> usize {
        self.inner.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }

    pub fn has_verified_finding(&self) -> bool {
        self.inner.node_weights().any(|node| {
            node.graph == GraphKind::Research
                && node.kind == "finding"
                && node.epistemic == EpistemicState::Verified
        })
    }

    pub fn reachable(&self, from: NodeId, to: NodeId) -> bool {
        let Some(start) = self.find_index(from) else {
            return false;
        };
        let Some(goal) = self.find_index(to) else {
            return false;
        };
        petgraph::algo::has_path_connecting(&self.inner, start, goal, None)
    }

    pub fn outgoing_kinds(&self, from: NodeId) -> Vec<String> {
        let Some(index) = self.find_index(from) else {
            return Vec::new();
        };
        self.inner
            .edges(index)
            .map(|edge| edge.weight().kind.clone())
            .collect()
    }
}
